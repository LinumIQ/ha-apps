"""
Caddy mTLS Proxy - Caddyfile snippets for experts (since 2.3.0).

Four optional files in the add-on's configuration folder (/config/caddy/ in
here, app_configs/<slug>/caddy/ on the host):

  global.caddy  imported at the START of the global options block (for an
                option given twice Caddy keeps the later one: the add-on's
                own email, storage, admin, grace_period win)
  site.caddy    in the public site's route: after the authentication gate
                and the header removal, before the proxy
  lan.caddy     in the local-network site's route: after its private-address
                checks, before the proxy
  sites.caddy   at the end of the Caddyfile: further sites and named snippets
                (``import mtls``: the add-on's strict client certificate check)

``customconf.py collect`` (init-caddy, at every start) writes README.txt into
the folder, decides which files count (a regular file - lstat before any
open, nothing else is ever opened -, at most MAX_BYTES, not empty after
trimming white space; lan.caddy only while the local-network port is on),
rejects files that import other files (the copies exist so that a run-time
reload never reads a live user file), and COPIES the counting files to
/etc/caddy/custom/ (0700/0600): the Caddyfile imports the copies. Caddy
2.11.9 reads CRLF line endings and a UTF-8 byte-order mark as they are
(verified), so the copies are byte for byte.

init-caddy then renders the Caddyfile with the copies, validates it, and -
because a valid file can still change the add-on's own blocks - runs
``customconf.py check``: the configuration Caddy builds (``caddy adapt``)
compared with the add-on's own rendering WITHOUT any custom file
(FALLBACK_FILE, ``check``, rules 1-4 in its docstring). Any failure: the
state is ``rejected``, all four files are dropped together (``reject``) and
the add-on starts with its own configuration only.

Files that a snippet refers to (a site's ``tls`` certificate and key, a
``trust_pool file``, CA files of a transport, ...) are not copied: Caddy reads
them at every (re)load. If one of them breaks after the start, a reload with
the snippets fails - and a revocation would not take effect. So the add-on's
own rendering is kept as FALLBACK_FILE while the snippets are in use, and a
reload that fails with them is retried with it (caddyctl.reload_detailed);
when that works, ``drop`` makes it permanent for the run: the Caddyfile
becomes the fallback, the copies go, the state is ``rejected`` with a
run-time marker (``dropped_at``). The files are read again at the next start.

The state for the panel's card and the monitor's notification is
STATE_FILE (``none`` | ``loaded`` | ``rejected``, the files that counted,
ignored entries with the reason, the error, the host folder). Standard
library only.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

FILES = ("global.caddy", "site.caddy", "lan.caddy", "sites.caddy")
MAX_BYTES = 256 * 1024
CONFIG_DIR = Path(os.environ.get("CADDY_MTLS_CUSTOM_SRC", "/config/caddy"))
COPY_DIR = Path(os.environ.get("CADDY_MTLS_CUSTOM_DIR", "/etc/caddy/custom"))
STATE_FILE = Path(os.environ.get("CADDY_MTLS_CUSTOM_STATE", "/run/caddy-mtls/custom.json"))
CADDYFILE = Path(os.environ.get("CADDYFILE", "/etc/caddy/Caddyfile"))
#: The add-on's own rendering (no custom import), kept while the custom
#: files are in use: the integrity check's reference, and what a reload
#: falls back to.
FALLBACK_FILE = Path(os.environ.get("CADDY_MTLS_FALLBACK_FILE", "/etc/caddy/Caddyfile.own"))
#: One lock around every reload sequence of the add-on (the panel, the
#: monitor, the caddy service's start): flock.
RELOAD_LOCK = Path(os.environ.get("CADDY_MTLS_RELOAD_LOCK", "/run/caddy-mtls/reload.lock"))
OPENSSL_BIN = os.environ.get("OPENSSL_BIN", "openssl")
ERROR_MAX = 2000
#: Caddy's message inside a run-time drop message.
CADDY_MESSAGE_MAX = 600
LAN_STATES = ("on", "off", "unknown")
DOCS_URL = "https://github.com/LinumIQ/ha-apps/blob/main/caddy-mtls/DOCS.md#custom-caddyfile-snippets-since-230"

README = f"""Caddy mTLS Proxy - Caddyfile snippets for experts (since 2.3.0)

Put any of these files into this folder; all are optional:

  global.caddy  global options - at the START of the add-on's global options
                block, so the add-on's own options (email, storage, admin,
                grace_period, its logs) win; do not repeat those
  site.caddy    directives for the public site - after the client certificate
                / header key check, before the proxy to Home Assistant; they
                run in the order written
  lan.caddy     directives for the local-network site (port 4443, only while
                it is on) - after its private-address check, before the proxy
  sites.caddy   further sites and named snippets; "import mtls" gives a site
                the add-on's strict client certificate check (with mTLS on);
                only on the add-on's ports 80, 443 and (while it is on) 4443,
                without "bind"

The files are applied when the add-on STARTS (from copies): restart it after
a change. Files they refer to (a "tls" certificate and key, a CA file, ...)
are read by Caddy at every reload, so a change of such a file takes effect at
the next reload. If Caddy rejects one of them, or it changes the add-on's own
sites, NONE of them is used and the add-on runs with its own configuration
only. If Caddy cannot reload with them any more while the add-on applies a
change (e.g. a revoked client), the add-on drops them until the next start,
so that the change takes effect. The add-on's web interface (card "Custom
Caddy configuration") and its log show the result and Caddy's message.

Documentation: {DOCS_URL}

This file is written by the add-on at every start.
"""

#: An import line: the directive (bare or quoted) and its argument.
_IMPORT = re.compile(r"""(?:^|[\s{])["'`]?import["'`]?(?=\s|$)(?P<rest>.*)$""")
_SNIPPET_NAME = re.compile(r"[A-Za-z0-9_-]+")


class CustomError(ValueError):
    """The custom files cannot be used (state rejected)."""

    def __init__(self, message: str, file: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.file = file


# ---------------------------------------------------------------------------
# Collect and copy
# ---------------------------------------------------------------------------

def _read_regular(path: Path) -> bytes | None:
    """The file's bytes if it is still a regular file when opened (no
    symlink followed, never blocking on a FIFO swapped in after lstat)."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks = []
        size = 0
        while size <= MAX_BYTES:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def import_error(name: str, data: bytes) -> str | None:
    """Why ``data`` (a custom file) must not be used because it imports a
    file, or None. Line based; quoted forms of the word count too; only
    ``import <snippet name>`` (``[A-Za-z0-9_-]+``) is allowed."""
    text = data.decode("utf-8", "replace").lstrip("﻿")
    for number, line in enumerate(text.splitlines(), 1):
        code = line.split("#", 1)[0] if not line.lstrip().startswith("#") else ""
        match = _IMPORT.search(code)
        if not match:
            continue
        args = match.group("rest").split()
        target = args[0].strip("\"'`") if args else ""
        if not _SNIPPET_NAME.fullmatch(target):
            return (
                f"caddy/{name}:{number} imports {('a file' if target else 'nothing')}: a custom file may "
                "only import a snippet by its name (for example import mtls), not other files - the "
                "add-on uses copies of your files, and an imported file would be read again unchecked "
                "at every reload"
            )
    return None


def collect(config_dir: Path, copy_dir: Path, lan: str = "on") -> dict[str, Any]:
    """Look at the four files, copy the counting ones. ``lan``: the
    local-network port's state (lan.caddy counts only while it is on).
    Returns {files, ignored, error, error_file} (error: the files must not
    be used)."""
    files: list[dict[str, Any]] = []
    ignored: list[dict[str, str]] = []
    if copy_dir.exists():
        shutil.rmtree(copy_dir)
    copy_dir.mkdir(mode=0o700, parents=True)
    os.chmod(copy_dir, 0o700)
    contents: dict[str, bytes] = {}
    for name in FILES:
        path = config_dir / name
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError as err:
            ignored.append({"name": name, "reason": f"cannot be read ({err.strerror or err})"})
            continue
        if name == "lan.caddy" and lan != "on":
            # Not imported anywhere (the local-network site does not exist),
            # so not validated either: never "in use".
            ignored.append({"name": name, "reason": "the local-network port is off" if lan == "off"
                            else "the local-network port's state is unknown (it stays off)"})
            continue
        if stat.S_ISLNK(st.st_mode):
            ignored.append({"name": name, "reason": "a symbolic link (only regular files are used)"})
            continue
        if not stat.S_ISREG(st.st_mode):
            ignored.append({"name": name, "reason": "not a regular file"})
            continue
        if st.st_size > MAX_BYTES:
            ignored.append({"name": name, "reason": f"larger than {MAX_BYTES // 1024} KiB ({st.st_size} bytes)"})
            continue
        try:
            data = _read_regular(path)
        except OSError as err:
            ignored.append({"name": name, "reason": f"cannot be read ({err.strerror or err})"})
            continue
        if data is None:
            ignored.append({"name": name, "reason": "not a regular file"})
            continue
        if len(data) > MAX_BYTES:
            ignored.append({"name": name, "reason": f"larger than {MAX_BYTES // 1024} KiB"})
            continue
        if not data.decode("utf-8", "replace").lstrip("﻿").strip():
            ignored.append({"name": name, "reason": "empty"})
            continue
        contents[name] = data
        files.append({"name": name, "bytes": len(data)})
    result: dict[str, Any] = {"files": files, "ignored": ignored, "error": "", "error_file": None}
    for name, data in contents.items():
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            result["error"] = f"caddy/{name} is not UTF-8 text"
            result["error_file"] = name
            break
        error = import_error(name, data)
        if error:
            result["error"], result["error_file"] = error, name
            break
    if result["error"]:
        return result
    for name, data in contents.items():
        target = copy_dir / name
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    return result


def write_readme(config_dir: Path) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    readme = config_dir / "README.txt"
    if readme.is_symlink():
        readme.unlink()
    fd, tmp = tempfile.mkstemp(prefix=".README.txt.", dir=str(config_dir))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(README)
        os.chmod(tmp, 0o644)
        os.replace(tmp, readme)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

def write_state(state: dict[str, Any], path: Path | None = None) -> None:
    path = STATE_FILE if path is None else path
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=1)
            fh.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def read_state(path: Path | None = None) -> dict[str, Any]:
    """The state of this start (``none`` when missing or unreadable)."""
    try:
        data = json.loads((path or STATE_FILE).read_text())
    except (OSError, ValueError):
        return {"state": "none", "files": [], "ignored": [], "error": "", "error_file": None, "folder": None}
    if not isinstance(data, dict) or data.get("state") not in ("none", "loaded", "rejected"):
        return {"state": "none", "files": [], "ignored": [], "error": "", "error_file": None, "folder": None}
    return data


def folder_name(slug: str) -> str | None:
    """The folder of the custom files as the official apps of today show
    it (Samba share, Terminal & SSH, File editor: ``app_configs``)."""
    return f"app_configs/{slug}/caddy" if slug else None


def legacy_folder(folder: str | None) -> str | None:
    """The same folder in apps that still map Supervisor's legacy name
    (``addon_configs``: older versions of those apps, and e.g. the community
    Advanced SSH & Web Terminal)."""
    if folder and folder.startswith("app_configs/"):
        return "addon_configs/" + folder[len("app_configs/"):]
    return None


def card_context(state: dict[str, Any]) -> dict[str, Any]:
    """The variables of the "Custom Caddy configuration" card
    (templates/_custom.html); shown only when files counted or entries were
    ignored."""
    files = [f for f in state.get("files") or [] if isinstance(f, dict) and f.get("name") in FILES]
    ignored = [i for i in state.get("ignored") or [] if isinstance(i, dict) and i.get("name") in FILES]
    st = state.get("state") if state.get("state") in ("none", "loaded", "rejected") else "none"
    folder = state.get("folder") if isinstance(state.get("folder"), str) else None
    return {
        "show": st in ("loaded", "rejected") or bool(ignored),
        "state": st,
        "files": files,
        "ignored": ignored,
        "error": str(state.get("error") or "")[:ERROR_MAX],
        "error_file": state.get("error_file") if state.get("error_file") in FILES else None,
        "folder": folder,
        "folder_legacy": legacy_folder(folder),
        "dropped": st == "rejected" and bool(state.get("dropped_at")),
        "docs_url": DOCS_URL,
    }


# ---------------------------------------------------------------------------
# Run time: the reload lock, and dropping the custom files
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def reload_lock(path: Path | None = None) -> Iterator[None]:
    """Hold the add-on's reload lock (exclusive flock on RELOAD_LOCK; waits
    for another holder). Not re-entrant: take it once per process."""
    path = RELOAD_LOCK if path is None else path
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


_HTTP_ERROR_BODY = re.compile(r"HTTP \d{3}: (\{.*\})\s*$")


def caddy_message(output: str, copy_dir: Path = COPY_DIR) -> str:
    """The cause in the output of a failed ``caddy reload`` / ``caddy
    validate``, for a message to the user: its last "Error:" line or error
    log line (the admin endpoint's {"error": ...} unwrapped), the copies
    named as the user's files, at most CADDY_MESSAGE_MAX characters. Scrub
    the header key before (headerauth.scrub)."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    message = ""
    for line in reversed(lines):
        if line.startswith("Error:"):
            message = line[len("Error:"):].strip()
            break
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get("level") == "error" and entry.get("msg"):
            message = str(entry["msg"]) + (f": {entry['error']}" if entry.get("error") else "")
            break
    if not message:
        message = lines[-1] if lines else "no message"
    body = _HTTP_ERROR_BODY.search(message)
    if body:
        with contextlib.suppress(ValueError, AttributeError):
            message = str(json.loads(body.group(1))["error"]) or message
    copy = re.escape(str(copy_dir).rstrip("/"))
    message = re.sub(copy + r"/((?:global|site|lan|sites)\.caddy)", r"caddy/\1", message)
    if len(message) > CADDY_MESSAGE_MAX:
        message = message[:CADDY_MESSAGE_MAX - 3] + "..."
    return message


def drop(cause: str, *, when: str = "reload", caddyfile: Path | None = None, fallback: Path | None = None,
         copy_dir: Path | None = None, state_path: Path | None = None) -> str:
    """Caddy runs the add-on's own configuration (FALLBACK_FILE) because it
    could not load the custom files any more (``cause``: caddy_message of
    Caddy's output): make that permanent for this run - the Caddyfile
    becomes the fallback (rename: atomic, and the fallback file is gone with
    it), the copies are removed, the state is ``rejected`` with the message
    and ``dropped_at`` (the run-time marker). ``when``: ``reload`` (a reload
    by the panel or the monitor) or ``restart`` (the caddy service started
    again). Returns the message. Call it with the reload lock held."""
    caddyfile = CADDYFILE if caddyfile is None else caddyfile
    fallback = FALLBACK_FILE if fallback is None else fallback
    copy_dir = COPY_DIR if copy_dir is None else copy_dir
    if when == "restart":
        message = (f"Caddy could not load the configuration with your custom files when it was started again "
                   f"({cause}). So that it runs, the add-on dropped them; they are read again at the next start "
                   "of the add-on.")
    else:
        message = (f"Caddy could not reload with your custom files while applying a change ({cause}). To apply "
                   "the change the add-on dropped them; they are read again at the next start.")
    # If the rename fails (the fallback file then still exists - callers log
    # that), Caddy runs the fallback all the same and the next reload falls
    # back again: the Caddyfile still imports the copies, which are gone.
    with contextlib.suppress(OSError):
        os.replace(fallback, caddyfile)
    shutil.rmtree(copy_dir, ignore_errors=True)
    state = read_state(state_path)
    state.update({"state": "rejected", "error": message[:ERROR_MAX], "error_file": None,
                  "dropped_at": time.time(), "dropped": when})
    write_state(state, state_path)
    return message


# ---------------------------------------------------------------------------
# Caddy's messages
# ---------------------------------------------------------------------------

_GENERATED = re.compile(r"(?:, )?at /etc/caddy/Caddyfile(?:\.[a-z]+)?:\d+")
_COPY = re.compile(r"/etc/caddy/custom/(global|site|lan|sites)\.caddy")


def describe_error(output: str, copy_dir: Path = COPY_DIR) -> tuple[str, str | None]:
    """A user-facing text of a failed ``caddy validate`` with custom files,
    and the file it names (None if Caddy names only the generated file)."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    message = ""
    for line in reversed(lines):
        try:
            entry = json.loads(line)
        except ValueError:
            entry = None
        if isinstance(entry, dict) and entry.get("level") == "error" and entry.get("msg"):
            message = str(entry["msg"])
            break
        if line.startswith("Error:"):
            message = line[len("Error:"):].strip()
            break
    if not message:
        message = lines[-1] if lines else "caddy validate failed"
    copy = re.escape(str(copy_dir).rstrip("/"))
    named = re.search(copy + r"/(global|site|lan|sites)\.caddy", message)
    message = re.sub(copy + r"/((?:global|site|lan|sites)\.caddy)", r"caddy/\1", message)
    message = re.sub(r" import chain \[[^\]]*\]", "", message)
    if named:
        message = _GENERATED.sub("", message)
        text = message
        file = f"{named.group(1)}.caddy"
    else:
        message = _GENERATED.sub("", message)
        text = (
            "Caddy names only the add-on's generated configuration, so the cause is in one of your "
            "files - usually a directive that is not allowed at that place (in site.caddy and "
            "lan.caddy only handler directives such as header, respond, rewrite, handle, "
            "reverse_proxy; tls, log or bind are site-level), or unbalanced braces. Caddy's "
            f"message: {message}"
        )
        file = None
    if len(text) > ERROR_MAX:
        text = text[:ERROR_MAX - 3] + "..."
    return text, file


# ---------------------------------------------------------------------------
# Integrity check
# ---------------------------------------------------------------------------

#: Server fields a custom file may change (performance and protocol
#: options; none of them decides who gets through or where a request goes).
FREE_SERVER_FIELDS = frozenset({
    "read_timeout", "read_header_timeout", "write_timeout", "idle_timeout", "keepalive_interval",
    "keepalive_idle", "keepalive_count", "max_header_bytes", "enable_full_duplex", "protocols",
    "listen_protocols", "metrics", "named_routes",
})
#: Checked separately (below).
SPECIAL_SERVER_FIELDS = frozenset({"routes", "errors", "tls_connection_policies", "strict_sni_host", "logs",
                                   "automatic_https"})
_SITE_LOGGER = re.compile(r"http\.log\.access\.log\d+")


class Violation(Exception):
    def __init__(self, rule: int, message: str, file: str | None = None) -> None:
        super().__init__(message)
        self.rule = rule
        self.message = message
        self.file = file


def _labels_overlap(pattern: str, domain: str) -> bool:
    """Can a host pattern match a request for ``domain`` (either side may
    hold wildcard labels, the add-on's domain option allows them)?
    Placeholders: assume yes."""
    pattern, domain = pattern.lower().rstrip("."), domain.lower().rstrip(".")
    if "{" in pattern:
        return True
    if pattern == domain:
        return True
    a, b = pattern.split("."), domain.split(".")
    if len(a) != len(b):
        return False
    return all(x == y or x == "*" or y == "*" for x, y in zip(a, b))


def _hosts_may_match(hosts: Any, domain: str) -> bool:
    if not isinstance(hosts, list):
        return True
    return any(isinstance(h, str) and _labels_overlap(h, domain) for h in hosts)


def route_may_match(route: dict[str, Any], domain: str) -> bool:
    """Could this route answer a request for ``domain`` (on its listener)?
    A matcher set without a host matcher can (paths, methods... do not
    exclude a host)."""
    sets = route.get("match")
    if not sets:
        return True
    for matchers in sets:
        if not isinstance(matchers, dict) or "host" not in matchers:
            return True
        if _hosts_may_match(matchers.get("host"), domain):
            return True
    return False


def _policy_may_match(policy: dict[str, Any], domain: str) -> bool:
    match = policy.get("match")
    if not isinstance(match, dict) or "sni" not in match:
        return True
    return _hosts_may_match(match.get("sni"), domain)


def _flatten(routes: list[Any]) -> list[dict[str, Any]]:
    """The handlers of a route list in order, each with its route's matcher
    and flags (Caddy merges consecutive matcher-less handlers into one
    route; flattening makes the comparison independent of that)."""
    items = []
    for route in routes:
        for handler in route.get("handle") or []:
            items.append({
                "match": route.get("match"),
                "terminal": route.get("terminal", False),
                "group": route.get("group"),
                "handler": handler,
            })
    return items


def _is_route_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(r, dict) and "handle" in r for r in value)


def _is_import_list(routes: Any, upstream: str) -> bool:
    """The route list the add-on renders a custom import into: its last
    handler is the add-on's own proxy to the upstream."""
    if not _is_route_list(routes):
        return False
    items = _flatten(routes)
    if not items:
        return False
    last = items[-1]["handler"]
    return (
        isinstance(last, dict) and last.get("handler") == "reverse_proxy"
        and [u.get("dial") for u in last.get("upstreams") or [] if isinstance(u, dict)] == [upstream]
    )


class _Comparer:
    """Deep comparison of the add-on's routes. Route "group" names (handle
    blocks that exclude each other) come from one counter over the whole
    Caddyfile, so a site you add shifts them: they are compared up to a
    consistent renaming (the same in both directions, over the whole check:
    ``groups``)."""

    def __init__(self, upstream: str, allow_run: bool, where: str, file: str | None,
                 groups: tuple[dict[str, str], dict[str, str]]) -> None:
        self.upstream = upstream
        self.allow_run = allow_run
        self.where = where
        self.file = file
        self.groups, self.groups_back = groups
        self.runs = 0

    def group(self, ref: Any, got: Any, path: str) -> None:
        if ref is None and got is None:
            return
        if (not isinstance(ref, str) or not isinstance(got, str)
                or self.groups.setdefault(ref, got) != got or self.groups_back.setdefault(got, ref) != ref):
            raise Violation(1, f"{self.where}: the grouping of handle blocks changed at {path}", self.file)

    def same(self, ref: Any, got: Any, path: str) -> None:
        if isinstance(ref, list) and _is_import_list(ref, self.upstream):
            self.import_list(ref, got, path)
            return
        if isinstance(ref, dict):
            if not isinstance(got, dict) or set(ref) != set(got):
                raise Violation(1, f"{self.where}: changed at {path}", self.file)
            for key in ref:
                if key == "group":
                    self.group(ref[key], got[key], f"{path}.group")
                else:
                    self.same(ref[key], got[key], f"{path}.{key}")
            return
        if isinstance(ref, list):
            if not isinstance(got, list) or len(ref) != len(got):
                raise Violation(1, f"{self.where}: changed at {path} (a route or handler was added or removed "
                                   "outside the place of your snippet - unbalanced braces?)", self.file)
            for i, (r, g) in enumerate(zip(ref, got)):
                self.same(r, g, f"{path}[{i}]")
            return
        if ref != got:
            raise Violation(1, f"{self.where}: changed at {path}", self.file)

    def import_list(self, ref: list[Any], got: Any, path: str) -> None:
        if not _is_route_list(got):
            raise Violation(1, f"{self.where}: the route with the proxy changed at {path}", self.file)
        r, g = _flatten(ref), _flatten(got)
        n = len(r)
        try:
            if len(g) < n:
                raise Violation(1, "too short")
            for i in range(n - 1):
                self.same(r[i], g[i], f"{path}<handler {i}>")
        except Violation:
            raise Violation(1, f"{self.where}: the add-on's handlers before your snippet changed (the "
                               "authentication gate must come first, unchanged)", self.file) from None
        try:
            self.same(r[-1], g[-1], f"{path}<last handler>")
        except Violation:
            raise Violation(1, f"{self.where}: the proxy to {self.upstream} is no longer the last handler, "
                               "unchanged", self.file) from None
        run = len(g) - n
        if run and not self.allow_run:
            raise Violation(1, f"{self.where}: handlers appeared that no snippet of this place contains", self.file)
        self.runs += 1


def _servers(config: dict[str, Any]) -> dict[str, Any]:
    servers = (((config.get("apps") or {}).get("http") or {}).get("servers")) or {}
    return servers if isinstance(servers, dict) else {}


def _automation_policy(config: dict[str, Any], domain: str) -> Any:
    policies = ((((config.get("apps") or {}).get("tls") or {}).get("automation") or {}).get("policies")) or []
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        subjects = policy.get("subjects")
        if not subjects or _hosts_may_match(subjects, domain):
            return policy
    return None


def _rename_path(value: Any, old: str, new: str) -> Any:
    """``value`` with every string equal to ``old`` replaced by ``new``."""
    if isinstance(value, dict):
        return {k: _rename_path(v, old, new) for k, v in value.items()}
    if isinstance(value, list):
        return [_rename_path(v, old, new) for v in value]
    return new if value == old else value


def check(adapted: dict[str, Any], reference: dict[str, Any], *, domain: str, upstream: str,
          files: list[str], header_auth: bool, config_path: str = "/etc/caddy/Caddyfile",
          reference_path: str = "/etc/caddy/Caddyfile.own",
          read_file: Callable[[str], bytes] | None = None) -> list[str]:
    """Compare what Caddy built with the custom files (``adapted``) with the
    rendering without them (``reference``). Returns the rules that hold
    (for the log); raises Violation for the first that does not.

    1. The add-on's routes are intact: in every server, the routes that can
       match the domain are the reference's, identical in every field -
       except that the route list of the public site (local-network site)
       holds the handlers of site.caddy (lan.caddy) as one contiguous run
       right before the add-on's proxy, which stays last; everything before
       the run (the gate, the header removal) is unchanged.
    2. The domain belongs to the add-on: no other route (also in error
       routes, also in new servers, also with a path or without a host)
       can match it.
    3. TLS for the domain is intact: the connection policies that can apply
       to the domain's SNI and the certificate automation policy equal the
       reference's; strict_sni_host is not switched off where the reference
       has client authentication.
    4. The machinery is intact: admin, storage, grace_period, the add-on's
       logs (a log you add must drop request headers too while a header key
       is set), the listeners of the add-on's servers and their other
       security-relevant fields (listener wrappers, trusted proxies, ...).
    """
    # Caddy names the file it read in places (file_server hides it): the
    # reference was rendered under another name.
    reference = _rename_path(reference, reference_path, config_path)
    rules: list[str] = []
    site_file = "site.caddy" if "site.caddy" in files else None
    lan_file = "lan.caddy" if "lan.caddy" in files else None
    only = files[0] if len(files) == 1 else None

    # 4 (top level).
    for key in ("admin", "storage"):
        if adapted.get(key) != reference.get(key):
            raise Violation(4, f"the {key} settings changed (the panel and the monitor need the add-on's own)",
                            "global.caddy")
    http_ref = (reference.get("apps") or {}).get("http") or {}
    http_got = (adapted.get("apps") or {}).get("http") or {}
    for key in ("grace_period", "http_port", "https_port"):
        if http_got.get(key) != http_ref.get(key):
            raise Violation(4, f"the global option {key} changed", "global.caddy")
    logs_ref = ((reference.get("logging") or {}).get("logs")) or {}
    logs_got = ((adapted.get("logging") or {}).get("logs")) or {}
    added = {f"http.log.access.{name}" for name in logs_got if name not in logs_ref}
    for name, log in logs_ref.items():
        got = logs_got.get(name)
        if not isinstance(got, dict) or not isinstance(log, dict):
            if got != log:
                raise Violation(4, f"the add-on's log {name} changed", only)
            continue
        # The adapter excludes every site's access logger from the default
        # log: a site you add (sites.caddy) adds its logger there.
        extra = set(got.get("exclude") or []) - set(log.get("exclude") or [])
        if ({k: v for k, v in got.items() if k != "exclude"} != {k: v for k, v in log.items() if k != "exclude"}
                or not set(log.get("exclude") or []) <= set(got.get("exclude") or [])
                or not all(_SITE_LOGGER.fullmatch(e) and e in added for e in extra)):
            raise Violation(4, f"the add-on's log {name} changed", only)
    if header_auth:
        for name, log in logs_got.items():
            if name in logs_ref:
                continue
            encoder = (log or {}).get("encoder") or {}
            fields = encoder.get("fields") or {}
            drops = encoder.get("format") == "filter" and any(
                key in ("request", "request>headers") and (value or {}).get("filter") == "delete"
                for key, value in fields.items())
            if not drops:
                raise Violation(4, f"the log {name} you added keeps request headers; while a header key is "
                                   "set every log must drop them (format filter { wrap console; "
                                   "request>headers delete })", only)
    rules.append("4: admin, storage, grace_period, the add-on's logs unchanged")

    servers_ref = _servers(reference)
    servers_got = _servers(adapted)
    groups: tuple[dict[str, str], dict[str, str]] = ({}, {})
    by_listen = {json.dumps(s.get("listen"), sort_keys=True): (n, s) for n, s in servers_got.items()}
    matched: set[str] = set()
    for name_ref, srv_ref in servers_ref.items():
        listen = json.dumps(srv_ref.get("listen"), sort_keys=True)
        if listen not in by_listen:
            raise Violation(4, f"the add-on's listener {srv_ref.get('listen')} is gone", "global.caddy")
        name_got, srv_got = by_listen[listen]
        matched.add(name_got)
        lan = srv_ref.get("listen") == [":4443"]
        where = ("the local-network site" if lan else "the public site" if srv_ref.get("listen") == [":443"]
                 else f"the add-on's site on {srv_ref.get('listen')}")
        # 4: the server's other fields.
        for key in set(srv_ref) | set(srv_got):
            if key in FREE_SERVER_FIELDS or key in SPECIAL_SERVER_FIELDS:
                continue
            if srv_ref.get(key) != srv_got.get(key):
                raise Violation(4, f"{where}: the server setting {key} changed", "global.caddy")
        # 1 + 2: the routes that can match the domain.
        for field in ("routes", "errors"):
            ref_routes = srv_ref.get(field) or []
            got_routes = srv_got.get(field) or []
            if field == "errors":
                ref_routes = (srv_ref.get("errors") or {}).get("routes") or []
                got_routes = (srv_got.get("errors") or {}).get("routes") or []
            ref_dom = [r for r in ref_routes if route_may_match(r, domain)]
            got_dom = [r for r in got_routes if route_may_match(r, domain)]
            if len(got_dom) != len(ref_dom):
                raise Violation(2, f"another route can answer {domain} on {srv_ref.get('listen')} (a site for the "
                                   "add-on's own host name - also with a path or a port -, a site without a "
                                   "host name, or braces that closed the add-on's site)",
                                "sites.caddy" if "sites.caddy" in files else only)
            comparer = _Comparer(upstream, allow_run=bool(lan_file if lan else site_file), where=where,
                                 file=(lan_file if lan else site_file) or only, groups=groups)
            for r, g in zip(ref_dom, got_dom):
                comparer.same(r, g, f"{field}")
        # 3: TLS.
        # Caddy merges host names with the same TLS settings into one
        # policy (a site of yours with "import mtls" joins the add-on's
        # strict policy): only the names that can be the domain count.
        def domain_part(policy: Any) -> Any:
            match = policy.get("match") if isinstance(policy, dict) else None
            if not isinstance(match, dict) or not isinstance(match.get("sni"), list):
                return policy
            sni = [h for h in match["sni"] if isinstance(h, str) and _labels_overlap(h, domain)]
            return dict(policy, match=dict(match, sni=sni))
        ref_pol = [domain_part(p) for p in srv_ref.get("tls_connection_policies") or [] if _policy_may_match(p, domain)]
        got_pol = [domain_part(p) for p in srv_got.get("tls_connection_policies") or [] if _policy_may_match(p, domain)]
        if ref_pol != got_pol:
            raise Violation(3, f"{where}: the TLS settings for {domain} changed (client authentication, "
                               "certificates)", "sites.caddy" if "sites.caddy" in files else only)
        has_client_auth = any(isinstance(p, dict) and p.get("client_authentication")
                              for p in srv_ref.get("tls_connection_policies") or [])
        if has_client_auth and srv_got.get("strict_sni_host") not in (None, True):
            raise Violation(3, f"{where}: strict_sni_host was switched off - with client certificates it must "
                               "stay on", "global.caddy")
        if not has_client_auth and srv_ref.get("strict_sni_host") != srv_got.get("strict_sni_host") \
                and srv_got.get("strict_sni_host") is False:
            raise Violation(3, f"{where}: strict_sni_host was switched off", "global.caddy")
        # 4: the add-on's access log mapping for the domain.
        ref_names = ((srv_ref.get("logs") or {}).get("logger_names")) or {}
        got_names = ((srv_got.get("logs") or {}).get("logger_names")) or {}
        for host, names in ref_names.items():
            if got_names.get(host) != names:
                raise Violation(4, f"{where}: the access log of {host} changed", only)
        for host in got_names:
            if host not in ref_names and _labels_overlap(host, domain):
                raise Violation(4, f"{where}: another access log was attached to {domain}", only)
        # (skip_hosts / skip_unmapped_hosts only ever log less.)
        if (srv_ref.get("logs") or {}).get("should_log_credentials") != \
                (srv_got.get("logs") or {}).get("should_log_credentials"):
            raise Violation(4, f"{where}: the access log setting log_credentials changed", "global.caddy")
        # 3 + 4: automatic HTTPS. A site you add with its own certificate
        # files adds its host to skip_certificates; nothing may touch the
        # domain's entries or switch anything off.
        ah_ref = srv_ref.get("automatic_https") or {}
        ah_got = srv_got.get("automatic_https") or {}
        for key in set(ah_ref) | set(ah_got):
            if key in ("skip", "skip_certificates"):
                ref_hosts, got_hosts = ah_ref.get(key) or [], ah_got.get(key) or []
                if any(h not in got_hosts for h in ref_hosts) or any(
                        isinstance(h, str) and _labels_overlap(h, domain) for h in got_hosts if h not in ref_hosts):
                    raise Violation(3, f"{where}: automatic HTTPS for {domain} changed ({key})", only)
            elif ah_ref.get(key) != ah_got.get(key):
                raise Violation(4, f"{where}: the automatic HTTPS setting {key} changed", "global.caddy")
    rules.append("1: the add-on's routes for the domain unchanged, custom handlers only at their place")
    # 4 (B-1): no server of its own for a site of yours. Every server must
    # listen exactly where one of the add-on's does: another port can take
    # one of the add-on's own listeners inside the container (2019: Caddy's
    # admin endpoint - a reload would go to your site and report success;
    # 8099: the web interface), and `bind` splits off a server that takes
    # the add-on's site on that address.
    for name_got, srv_got in servers_got.items():
        if name_got in matched:
            continue
        listen = ", ".join(str(a) for a in srv_got.get("listen") or []) or "(no address)"
        raise Violation(4, f"a site of yours listens on {listen}: your sites can use only the add-on's own ports "
                           "80, 443 and (while the local-network port is on) 4443, without bind - the add-on "
                           "publishes no other port, and ports such as 2019 (Caddy's admin interface) and 8099 "
                           "(this web interface) belong to the add-on",
                        "sites.caddy" if "sites.caddy" in files else only)
    rules.append("2: no other route can answer the domain")
    # The adapter merges host names with the same TLS settings into one
    # policy: its subjects may grow by a site you add, its settings may not.
    def settings(policy: Any) -> Any:
        return {k: v for k, v in policy.items() if k != "subjects"} if isinstance(policy, dict) else policy
    if settings(_automation_policy(adapted, domain)) != settings(_automation_policy(reference, domain)):
        raise Violation(3, f"the certificate settings for {domain} changed",
                        "global.caddy" if "global.caddy" in files else only)
    rules.append("3: TLS for the domain unchanged")
    return rules


# ---------------------------------------------------------------------------
# init-caddy
# ---------------------------------------------------------------------------

def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = parser.add_subparsers(dest="command", required=True)
    col = sub.add_parser("collect", help="README, decide which files count, copy them, write the state")
    col.add_argument("--config-dir", type=Path, default=CONFIG_DIR)
    col.add_argument("--copy-dir", type=Path, default=COPY_DIR)
    col.add_argument("--state", type=Path, default=STATE_FILE)
    col.add_argument("--slug", default="")
    col.add_argument("--lan", choices=LAN_STATES, required=True, help="the local-network port's state")
    chk = sub.add_parser("check", help="integrity check of the adapted configuration")
    chk.add_argument("--adapted", type=Path, required=True)
    chk.add_argument("--reference", type=Path, required=True)
    chk.add_argument("--domain", required=True)
    chk.add_argument("--upstream", required=True)
    chk.add_argument("--header-auth", choices=("true", "false"), required=True)
    chk.add_argument("--state", type=Path, default=STATE_FILE)
    rej = sub.add_parser("reject", help="drop the copies, state rejected with the message")
    rej.add_argument("--copy-dir", type=Path, default=COPY_DIR)
    rej.add_argument("--state", type=Path, default=STATE_FILE)
    group = rej.add_mutually_exclusive_group(required=True)
    group.add_argument("--validate-output", type=Path, help="Caddy's (scrubbed) validate output")
    group.add_argument("--message", help="the reason")
    rej.add_argument("--file", default=None)
    drp = sub.add_parser("drop", help="Caddy runs the add-on's own configuration: drop the custom files for this "
                                      "run (takes the reload lock)")
    drp.add_argument("--output", type=Path, required=True, help="Caddy's output (why it could not load them)")
    drp.add_argument("--when", choices=("reload", "restart"), default="restart")
    drp.add_argument("--caddyfile", type=Path, default=CADDYFILE)
    drp.add_argument("--fallback", type=Path, default=FALLBACK_FILE)
    drp.add_argument("--copy-dir", type=Path, default=COPY_DIR)
    drp.add_argument("--state", type=Path, default=STATE_FILE)
    drp.add_argument("--lock", type=Path, default=RELOAD_LOCK)
    args = parser.parse_args(argv)

    if args.command == "collect":
        state: dict[str, Any] = {"state": "none", "files": [], "ignored": [], "error": "", "error_file": None,
                                 "folder": folder_name(args.slug), "checked_at": time.time()}
        if args.config_dir.parent.is_dir():
            write_readme(args.config_dir)
            result = collect(args.config_dir, args.copy_dir, args.lan)
            state.update(result)
            if result["error"]:
                state["state"] = "rejected"
                shutil.rmtree(args.copy_dir, ignore_errors=True)
            elif result["files"]:
                state["state"] = "loaded"
        else:
            shutil.rmtree(args.copy_dir, ignore_errors=True)
        write_state(state, args.state)
        print(json.dumps(state))
        return 0

    if args.command == "check":
        state = read_state(args.state)
        files = [f["name"] for f in state.get("files") or [] if isinstance(f, dict)]
        try:
            adapted = json.loads(args.adapted.read_text())
            reference = json.loads(args.reference.read_text())
            rules = check(adapted, reference, domain=args.domain, upstream=args.upstream, files=files,
                          header_auth=args.header_auth == "true")
        except Violation as err:
            where = f" ({err.file})" if err.file else ""
            print(json.dumps({"ok": False, "rule": err.rule, "file": err.file,
                              "message": f"rule {err.rule}{where}: {err.message}"}))
            return 3
        except (OSError, ValueError) as err:
            print(json.dumps({"ok": False, "rule": 0, "file": None,
                              "message": f"the integrity check could not run ({type(err).__name__})"}))
            return 3
        print(json.dumps({"ok": True, "rules": rules}))
        return 0

    if args.command == "drop":
        import headerauth  # the panel's module, next to this one
        cause = caddy_message(headerauth.scrub(args.output.read_text(errors="replace")), args.copy_dir)
        with reload_lock(args.lock):
            if not args.fallback.exists():
                print("no fallback configuration: nothing dropped", file=sys.stderr)
                return 1
            message = drop(cause, when=args.when, caddyfile=args.caddyfile, fallback=args.fallback,
                           copy_dir=args.copy_dir, state_path=args.state)
        print(message)
        return 0 if not args.fallback.exists() else 1

    # reject
    state = read_state(args.state)
    if args.validate_output:
        text, file = describe_error(args.validate_output.read_text(errors="replace"))
    else:
        text, file = args.message[:ERROR_MAX], args.file
    state.update({"state": "rejected", "error": text, "error_file": file if file in FILES else None})
    shutil.rmtree(args.copy_dir, ignore_errors=True)
    write_state(state, args.state)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
