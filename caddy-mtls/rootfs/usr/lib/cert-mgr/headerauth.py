"""
Caddy mTLS Proxy - header authentication (since 2.3.0).

Some clients cannot present a client certificate but can add one fixed
header to every request (e.g. a watch app). With ``header_auth_key`` set,
the public site accepts a request that presents an active client
certificate OR carries the header ``header_auth_name`` with exactly the key.

This module owns the key at the start (init-caddy runs
``headerauth.py setup``):

  * it reads both options from the add-on's options file itself, so the key
    never passes through a shell variable, the environment or a command line;
  * it validates them (a violation refuses the start; no message contains
    the key or a part of it - its length may be named);
  * it writes the key to KEY_FILE (0600, no line break), the only copy the
    add-on makes. Caddy reads it per request through the ``{file.<path>}``
    placeholder; the Caddyfile never contains the key. Header
    authentication off: the file is removed;
  * it prints the facts for runtime.json: on/off, the header name, the key's
    length - never the key.

``headerauth.py scrub`` copies stdin to stdout with the key (read from
KEY_FILE) replaced by ``<redacted>``: the second line behind the first (the
key is never in the configuration, so Caddy's output cannot contain it).

The panel's "Header authentication" card (card_context) reads only
runtime.json. Standard library only.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

OPTIONS_FILE = Path(os.environ.get("CADDY_MTLS_OPTIONS_FILE", "/data/options.json"))
KEY_FILE = Path(os.environ.get("CADDY_MTLS_HEADER_KEY_FILE", "/etc/caddy/header-auth.key"))

DEFAULT_NAME = "X-Custom-PSK"
KEY_MIN = 32
KEY_MAX = 256
#: The key's characters: outside this set a value could turn into a
#: wildcard (* at either end), a placeholder ({...}, {$...}), a comment (#),
#: a heredoc (<<), two tokens (a blank) or a quoted token in the Caddyfile's
#: header matcher (REPORT-I I-4) - and a line break or a blank would be
#: trimmed by some HTTP stacks.
KEY_RE = re.compile(r"[A-Za-z0-9._~+/=-]+")
KEY_CHARSET = "letters A-Z and a-z, digits 0-9 and the characters . _ ~ + / = -"
NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,63}")
#: Header names Home Assistant, browsers or the proxy machinery use
#: (compared case-insensitively).
RESERVED_NAMES = frozenset(name.lower() for name in (
    "Authorization", "Cookie", "Set-Cookie", "Host", "Connection", "Upgrade",
    "Content-Length", "Content-Type", "Transfer-Encoding", "TE", "Trailer",
    "Keep-Alive", "Origin", "Referer", "User-Agent", "Forwarded", "X-Real-IP",
    "Via", "Range", "Expect", "Date",
))
RESERVED_PREFIXES = tuple(prefix.lower() for prefix in (
    "Accept", "Sec-", "Proxy-", "If-", "Cache-", "Content-", "X-Forwarded-",
    "X-Hass", "X-Ingress", "X-Supervisor", "X-HA-", "CF-",
))
HOW_TO_MAKE_A_KEY = (
    "The add-on's web interface suggests one (card \"Header authentication\", "
    "Suggest a key), or run: openssl rand -base64 32"
)


class OptionError(ValueError):
    """A header authentication option is not acceptable (the message never
    contains the key)."""


def name_error(name: str) -> str | None:
    """Why ``name`` cannot be the header's name, or None."""
    if not NAME_RE.fullmatch(name):
        return (
            f"header_auth_name {json.dumps(name)} is not a header name for this add-on: 1-64 "
            f"characters, a letter first, then letters, digits or '-' (for example {DEFAULT_NAME})."
        )
    lower = name.lower()
    if lower in RESERVED_NAMES or lower.startswith(RESERVED_PREFIXES):
        return (
            f"header_auth_name {json.dumps(name)} is a header that browsers, Home Assistant or the "
            f"proxy itself use; choose a name of your own, for example {DEFAULT_NAME}."
        )
    return None


def key_error(key: Any) -> str | None:
    """Why ``key`` cannot be the pre-shared key, or None. Never quotes the
    key or a part of it."""
    if not isinstance(key, str):
        return "header_auth_key must be text."
    if len(key) < KEY_MIN or len(key) > KEY_MAX:
        return (
            f"header_auth_key has {len(key)} characters; it needs {KEY_MIN} to {KEY_MAX} "
            f"({KEY_CHARSET}). {HOW_TO_MAKE_A_KEY}."
        )
    if not KEY_RE.fullmatch(key):
        return (
            f"header_auth_key contains a character that is not allowed (for example a blank, "
            f"a line break, '*', '{{' or '}}'; nothing is trimmed). Allowed: {KEY_CHARSET}. "
            f"{HOW_TO_MAKE_A_KEY}."
        )
    return None


def read_options(path: Path) -> tuple[str, str]:
    """(header name, key) from the options file; defaults for options saved
    before 2.3.0 (neither key) or left empty."""
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as err:
        raise OptionError(f"Could not read the add-on's options ({path}: {type(err).__name__}).") from None
    if not isinstance(data, dict):
        raise OptionError(f"Could not read the add-on's options ({path}: not an object).")
    name = data.get("header_auth_name")
    if name is None or name == "":
        name = DEFAULT_NAME
    if not isinstance(name, str):
        raise OptionError("header_auth_name must be text.")
    key = data.get("header_auth_key")
    if key is None:
        key = ""
    return name, key


def write_key(key: str, path: Path) -> None:
    """The key file: 0600, root, written atomically, no line break."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(key)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def setup(options: Path = OPTIONS_FILE, key_file: Path = KEY_FILE) -> dict[str, Any]:
    """Validate, write or remove the key file; the facts for runtime.json.
    Raises OptionError (the start is refused)."""
    name, key = read_options(options)
    if not isinstance(key, str):
        raise OptionError("header_auth_key must be text.")
    if key == "":
        with contextlib.suppress(FileNotFoundError):
            key_file.unlink()
        # The name is not used while the feature is off; a bad one is still
        # reported (Supervisor's schema refuses it as well).
        return {"enabled": False, "name": name if name_error(name) is None else DEFAULT_NAME, "key_length": 0}
    error = name_error(name) or key_error(key)
    if error:
        raise OptionError(error)
    write_key(key, key_file)
    return {"enabled": True, "name": name, "key_length": len(key)}


def scrub(text: str, key_file: Path | None = None) -> str:
    """``text`` with the key replaced by <redacted> (unchanged without a
    readable, non-empty key file; default KEY_FILE)."""
    key_file = KEY_FILE if key_file is None else key_file
    try:
        key = key_file.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError):
        return text
    return text.replace(key, "<redacted>") if key else text


# ---------------------------------------------------------------------------
# Panel
# ---------------------------------------------------------------------------

def facts(runtime: dict[str, Any] | None) -> dict[str, Any]:
    """The header authentication facts of runtime.json (defaults: off)."""
    data = (runtime or {}).get("header_auth")
    if not isinstance(data, dict):
        data = {}
    name = data.get("name")
    length = data.get("key_length")
    return {
        "enabled": data.get("enabled") is True,
        "name": name if isinstance(name, str) and NAME_RE.fullmatch(name) else DEFAULT_NAME,
        "key_length": length if isinstance(length, int) and length >= 0 else 0,
    }


def card_context(runtime: dict[str, Any] | None) -> dict[str, Any]:
    """The variables of the "Header authentication" card
    (templates/_headerauth.html)."""
    rt = runtime or {}
    ha = facts(rt)
    return {
        "known": bool(rt),
        "state": "on" if ha["enabled"] else "off",
        "name": ha["name"],
        "key_length": ha["key_length"],
        "mtls": rt.get("mtls_enabled") is not False,
        "access_log": rt.get("access_log") is True,
        "key_min": KEY_MIN,
        "key_max": KEY_MAX,
        "charset": KEY_CHARSET,
        "default_name": DEFAULT_NAME,
    }


# ---------------------------------------------------------------------------
# init-caddy
# ---------------------------------------------------------------------------

def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = parser.add_subparsers(dest="command", required=True)
    setup_cmd = sub.add_parser("setup", help="validate the options, write or remove the key file")
    setup_cmd.add_argument("--options", type=Path, default=OPTIONS_FILE)
    setup_cmd.add_argument("--key-file", type=Path, default=KEY_FILE)
    scrub_cmd = sub.add_parser("scrub", help="stdin -> stdout with the key redacted")
    scrub_cmd.add_argument("--key-file", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.command == "scrub":
        for line in sys.stdin:
            sys.stdout.write(scrub(line, args.key_file))
        return 0
    try:
        result = setup(args.options, args.key_file)
    except OptionError as err:
        print(str(err), file=sys.stderr)
        return 2
    except OSError as err:
        print(f"Could not write the header authentication key file ({type(err).__name__}).", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
