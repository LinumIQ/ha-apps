"""
Caddy mTLS Proxy - certificate expiry monitor.

Periodically reads /data/state.json, computes days-to-expiry for each
certificate, and:
  * publishes a Home Assistant sensor entity per cert via the Supervisor
    REST API (so Home Assistant can build automations / dashboards on
    them);
  * fires a persistent notification via the same API when a cert crosses
    one of the configured warning thresholds (default 30 / 14 / 7 / 1
    days). Each (cert, threshold) is fired only once until the cert is
    rotated.

It also watches the public (Let's Encrypt) server certificate
(public_cert.py): while there is none - and for the first 30 minutes after
the start - it checks every minute; after 2 minutes without a certificate it
raises a persistent notification with the last ACME error and a port
forwarding checklist, and dismisses it as soon as the certificate exists. The
add-on log gets one line per change of that state.

It watches the upstream (upstream.py) as well: a control request every
UPSTREAM_CONTROL_INTERVAL seconds on a kept-alive connection (every
UPSTREAM_FAST_INTERVAL seconds while the upstream does not answer, restarts
or a test is owed - for the first UPSTREAM_FAST_WINDOW seconds of a period
without an answer); when the upstream answers again after it was unreachable
or restarted, the test request (does it accept forwarded requests?), which
switches the forwarding mode at run time. Under forwarded_headers: auto in
mode pass the test also runs every UPSTREAM_TEST_INTERVAL seconds (Home
Assistant logs nothing while it trusts the add-on). While every request is
answered "400: Bad Request" (refused, mode pass) a persistent notification is
raised; another one when the add-on starts hiding the visitor addresses at
run time because the upstream stopped trusting it; each is dismissed when
that is over.

Failure to reach the Supervisor never crashes the loop - we log and try
again on the next iteration.

Entity ids: Home Assistant accepts only ``[a-z0-9_]`` object ids without a
leading / trailing ``_`` and without ``__``, so a client's sensor is
``sensor.caddy_mtls_client_<slug>_expiry`` with ``<slug>`` from
``client_entity_slugs`` (e.g. ``alice-phone`` -> ``alice_phone``); the raw
client name stays in the friendly name.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest

import public_cert
import upstream

LOG = logging.getLogger("cert-monitor")
logging.basicConfig(
    level=os.environ.get("CERT_MGR_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

STATE_FILE = Path(os.environ.get("STATE_FILE", "/data/state.json"))
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
SUPERVISOR_URL = os.environ.get("SUPERVISOR_URL", "http://supervisor")
INTERVAL_SECONDS = int(os.environ.get("CERT_CHECK_INTERVAL_SECONDS", "21600"))
THRESHOLDS_RAW = os.environ.get("CERT_EXPIRY_WARN_DAYS", "30,14,7,1")
THRESHOLDS = sorted(
    {int(s.strip()) for s in THRESHOLDS_RAW.split(",") if s.strip()},
    reverse=True,
)

# Public certificate watch: check interval while there is no certificate and
# during the first FAST_LANE_SECONDS after the start, and how long the
# certificate may be missing before the notification is raised. (Overridable
# for tests only.)
PUBLIC_CERT_FAST_INTERVAL = int(os.environ.get("CERT_MONITOR_FAST_INTERVAL_SECONDS", "60"))
PUBLIC_CERT_GRACE_SECONDS = int(os.environ.get("CERT_MONITOR_PUBLIC_CERT_GRACE_SECONDS", "120"))
FAST_LANE_SECONDS = int(os.environ.get("CERT_MONITOR_FAST_LANE_SECONDS", "1800"))
PUBLIC_CERT_NOTIFICATION_ID = "caddy_mtls_public_certificate"

# Upstream watch (upstream.py): the control request's interval, the test
# request's interval in mode pass under auto, the control interval while the
# upstream does not answer (or restarts, or a test is owed), the notifications
# "every request is answered 400" and "addresses hidden at run time".
# (Overridable for tests only.) The fast interval holds for the first
# UPSTREAM_FAST_WINDOW seconds of a period without an answer (also from the
# add-on's start); after that the control interval, until it answers again.
UPSTREAM_CONTROL_INTERVAL = float(os.environ.get("CADDY_MTLS_UPSTREAM_CONTROL_SECONDS", "12"))
UPSTREAM_TEST_INTERVAL = float(os.environ.get("CADDY_MTLS_UPSTREAM_TEST_SECONDS", "60"))
UPSTREAM_FAST_INTERVAL = float(os.environ.get("CADDY_MTLS_UPSTREAM_FAST_SECONDS", "2.5"))
UPSTREAM_FAST_WINDOW = 600.0
UPSTREAM_NOTIFICATION_ID = "caddy_mtls_upstream_refuses"
UPSTREAM_HIDDEN_NOTIFICATION_ID = "caddy_mtls_upstream_addresses_hidden"

# Tracks which (cert_id, threshold_days) pairs we've already notified for
# in the current state, so we don't spam HA on every loop iteration.
NOTIFIED_FILE = Path(
    os.environ.get("CERT_MONITOR_NOTIFIED_FILE", "/data/cert-monitor.notified.json")
)


_SLUG_SEPARATORS = re.compile(r"[^a-z0-9]+")


def entity_slug(name: str) -> str:
    """Object-id slug of a client name for a Home Assistant entity id.

    Lowercase; every run of characters other than ``[a-z0-9]`` becomes one
    ``_`` (so ``__`` cannot occur); no leading or trailing ``_``. May be
    empty (e.g. for ``"_"``) - see ``client_entity_slugs``.
    """
    return _SLUG_SEPARATORS.sub("_", name.lower()).strip("_")


def client_entity_slugs(names: Iterable[str]) -> dict[str, str]:
    """A unique entity-id slug per client name.

    Names are taken in the given order (state.json order, revoked clients
    included, so a client's sensor keeps its id when another one is revoked
    or added later): the first name with a slug gets the plain slug; a later
    name with the same slug, or a name without any ``[a-z0-9]`` character,
    gets a short hash of the raw name appended (``alice-phone`` after
    ``alice.phone``: ``alice_phone_66287d``).
    """
    slugs: dict[str, str] = {}
    used: set[str] = set()
    for name in names:
        if name in slugs:
            continue
        base = entity_slug(name)
        slug = base
        if not slug or slug in used:
            digest = hashlib.sha256(name.encode("utf-8", "surrogatepass")).hexdigest()
            prefix = f"{base}_" if base else ""
            slug = next(
                (
                    candidate
                    for candidate in (prefix + digest[:n] for n in range(6, len(digest) + 1))
                    if candidate not in used
                ),
                f"{prefix}{digest}_{len(used)}",
            )
        used.add(slug)
        slugs[name] = slug
    return slugs


def _read_state() -> dict[str, Any]:
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        LOG.error("Failed to read state: %s", exc)
        return {}


def _read_notified() -> dict[str, int]:
    if not NOTIFIED_FILE.exists():
        return {}
    try:
        return json.loads(NOTIFIED_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _write_notified(data: dict[str, int]) -> None:
    try:
        NOTIFIED_FILE.write_text(json.dumps(data))
    except OSError as exc:
        LOG.warning("Failed to persist notified state: %s", exc)


def _supervisor_request(method: str, path: str, payload: dict[str, Any] | None = None) -> bool:
    if not SUPERVISOR_TOKEN:
        LOG.debug("No SUPERVISOR_TOKEN; skipping Supervisor call %s %s", method, path)
        return False
    url = f"{SUPERVISOR_URL}{path}"
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urlrequest.Request(url, data=body, method=method)
    req.add_header("Authorization", f"Bearer {SUPERVISOR_TOKEN}")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urlrequest.urlopen(req, timeout=10) as resp:
            if resp.status >= 400:
                LOG.warning("Supervisor %s %s returned %d", method, path, resp.status)
                return False
            return True
    except urlerror.HTTPError as exc:
        # Reading body may help debugging.
        try:
            detail = exc.read().decode("utf-8", "replace")
        except Exception:
            detail = ""
        LOG.warning("Supervisor %s %s failed: %s %s", method, path, exc, detail[:200])
        return False
    except (urlerror.URLError, TimeoutError, OSError) as exc:
        LOG.warning("Supervisor %s %s failed: %s", method, path, exc)
        return False


def _publish_sensor(slug: str, friendly: str, days_left: int, not_after: str) -> bool:
    """Push a sensor state to Home Assistant via the Supervisor proxy."""
    entity_id = f"sensor.caddy_mtls_{slug}_expiry"
    payload = {
        "state": days_left,
        "attributes": {
            "friendly_name": f"Caddy mTLS {friendly} expiry",
            "unit_of_measurement": "d",
            "icon": "mdi:certificate-outline",
            "not_after": not_after,
        },
    }
    return _supervisor_request("POST", f"/core/api/states/{entity_id}", payload)


def _send_notification(title: str, message: str, notification_id: str) -> bool:
    payload = {
        "title": title,
        "message": message,
        "notification_id": notification_id,
    }
    return _supervisor_request(
        "POST",
        "/core/api/services/persistent_notification/create",
        payload,
    )


def _dismiss_notification(notification_id: str) -> bool:
    return _supervisor_request(
        "POST",
        "/core/api/services/persistent_notification/dismiss",
        {"notification_id": notification_id},
    )


def _days_until(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        # state.sh writes ISO8601 with Z or offset.
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        LOG.warning("Could not parse not_after: %r", iso)
        return None
    now = datetime.now(timezone.utc)
    return int((dt - now).total_seconds() // 86400)


def _crossed_threshold(days_left: int, last_notified: int | None) -> int | None:
    """Return the threshold to notify for, or None.

    THRESHOLDS is sorted high-to-low (e.g. 30, 14, 7, 1). We pick the
    lowest threshold the cert is already at-or-below (i.e. the most
    urgent), and only re-notify if that threshold is *more urgent* than
    the previously notified one. This means each cert fires at most one
    notification per iteration and never duplicates the same warning.
    """
    most_urgent: int | None = None
    for t in THRESHOLDS:  # high to low
        if days_left <= t:
            most_urgent = t  # keep walking; later (smaller) values overwrite
    if most_urgent is None:
        return None
    if last_notified is None or most_urgent < last_notified:
        return most_urgent
    return None


def _process_once() -> bool:
    """Run a single monitor iteration.

    Returns True iff at least one sensor was successfully published to
    Home Assistant during this iteration. Used by the startup loop to
    decide when HA Core is finally reachable.
    """
    state = _read_state()
    if not state:
        return False
    notified = _read_notified()
    any_published = False

    # (key, entity-id slug, friendly name, metadata). The key (raw client
    # name) identifies the certificate in the notified file.
    items: list[tuple[str, str, str, dict[str, Any]]] = []
    if state.get("ca"):
        items.append(("ca", "ca", "CA", state["ca"]))
    clients = [
        c
        for c in state.get("clients", [])
        if isinstance(c, dict) and isinstance(c.get("name"), str) and c["name"]
    ]
    slugs = client_entity_slugs(c["name"] for c in clients)
    for c in clients:
        if c.get("status") == "active":
            name = c["name"]
            items.append((f"client_{name}", f"client_{slugs[name]}", f"client {name}", c))

    new_notified = dict(notified)
    for key, slug, friendly, meta in items:
        days_left = _days_until(meta.get("not_after"))
        if days_left is None:
            continue
        if _publish_sensor(slug, friendly, days_left, meta.get("not_after", "")):
            any_published = True

        # Identify cert by serial so rotation resets the notification state.
        identity = f"{key}:{meta.get('serial','')}"
        last = notified.get(identity)
        threshold = _crossed_threshold(days_left, last)
        if threshold is not None:
            _send_notification(
                title=f"Caddy mTLS: {friendly} expires in {days_left} day(s)",
                message=(
                    f"The {friendly} certificate (serial "
                    f"{meta.get('serial','?')}) expires on "
                    f"{meta.get('not_after','?')}. "
                    "Rotate it via the add-on's certificate manager UI."
                ),
                notification_id=f"caddy_mtls_{slug}_expiry",
            )
            new_notified[identity] = threshold

    # Drop entries whose identity is no longer present (cert rotated/removed).
    current_ids = {f"{key}:{meta.get('serial','')}" for key, _, _, meta in items}
    new_notified = {k: v for k, v in new_notified.items() if k in current_ids}
    if new_notified != notified:
        _write_notified(new_notified)
    return any_published


def _notification_message(status: public_cert.Status) -> str:
    """Markdown text of the "no public certificate" notification."""
    domain = status.domain
    lines = [
        f"Caddy could not get a public (Let's Encrypt) certificate for "
        f"**{domain}** yet, so {domain} is not reachable over HTTPS.",
        "",
    ]
    if status.last_error:
        lines += [
            f"Last error ({public_cert.local_time(status.last_error.ts)}): "
            f"{status.last_error.text}",
            "",
        ]
    lines.append("Please check:")
    lines += [f"- {item}" for item in public_cert.checklist(status)]
    lines += [
        "",
        public_cert.retry_hint(status),
        "The app's web interface (Caddy mTLS) shows the current state.",
    ]
    return "\n".join(lines)


class PublicCertWatch:
    """State machine for the public certificate notification.

    States: ``None`` (not checked yet), ``"ok"`` (a valid certificate),
    ``"missing"`` (none, for less than PUBLIC_CERT_GRACE_SECONDS),
    ``"notified"`` (none for longer: the notification is raised). The add-on
    log gets one line per change of state; the Supervisor is called only to
    raise the notification (retried until it succeeds) and to dismiss it once
    the certificate exists (also at the first check after a start: a
    notification of a previous run may still be shown).
    """

    def __init__(self, started: float) -> None:
        self.started = started
        self.state: str | None = None
        self.missing_since: float | None = None
        self._raised = False
        self._dismiss_pending = False

    def check(self, now: float, status: public_cert.Status) -> None:
        if status.state == "unknown":
            LOG.debug("public certificate: no runtime information yet")
            return
        if status.has_valid_certificate:
            self.missing_since = None
            if self.state != "ok":
                cert = status.certificate
                assert cert is not None
                LOG.info(
                    "Public certificate for %s: %s, valid until %s (%d days).",
                    status.domain,
                    cert.issuer,
                    cert.not_after.strftime("%Y-%m-%d"),
                    cert.days_left(status.now),
                )
                self.state = "ok"
                self._dismiss_pending = True
            if self._dismiss_pending and _dismiss_notification(PUBLIC_CERT_NOTIFICATION_ID):
                self._dismiss_pending = False
                self._raised = False
            return

        self._dismiss_pending = False
        if self.missing_since is None:
            self.missing_since = now
        if now - self.missing_since < PUBLIC_CERT_GRACE_SECONDS:
            self.state = "missing"
            return
        if self.state != "notified":
            error = status.last_error.text if status.last_error else "no error logged yet"
            LOG.warning(
                "No public certificate for %s after %d minutes - last error: %s. "
                "Check the router's port forwarding (details in the app's web "
                "interface), then restart the app to retry immediately.",
                status.domain,
                int((now - self.missing_since) // 60),
                error,
            )
            self.state = "notified"
        if not self._raised:
            self._raised = _send_notification(
                title=f"Caddy mTLS: no public certificate for {status.domain}",
                message=_notification_message(status),
                notification_id=PUBLIC_CERT_NOTIFICATION_ID,
            )

    def interval(self, now: float) -> float:
        """Seconds until the next check."""
        if self.state != "ok" or now - self.started < FAST_LANE_SECONDS:
            return PUBLIC_CERT_FAST_INTERVAL
        return INTERVAL_SECONDS


def upstream_notification(settings: upstream.Settings, state: upstream.State) -> tuple[str, str]:
    """Title and Markdown text of the "every request is answered 400"
    notification."""
    name = upstream.upstream_name(settings)
    source = state.source_address or "this add-on"
    suggestion = upstream.trusted_proxy_suggestion(state.source_address)
    title = (
        "Caddy mTLS: Home Assistant refuses the proxied requests"
        if settings.is_home_assistant
        else "Caddy mTLS: the upstream refuses the proxied requests"
    )
    why = (
        "forwarded_headers is `always`"
        if settings.option == "always" and settings.mtls
        else "mTLS is off (`mtls_enabled: false`), so the add-on never hides the visitor "
        "addresses: every internet visitor would look like a local device"
    )
    lines = [
        f'Every request through **{settings.domain}** is answered "400: Bad Request": '
        f"{name} does not trust this add-on ({source}) as a reverse proxy, and the add-on "
        f"passes the visitor addresses on ({why}).",
        "",
        "To fix it:",
    ]
    lines += [f"{n}. {step}" for n, step in enumerate(upstream.fix_steps(settings, suggestion), 1)]
    if settings.is_home_assistant:
        lines += [
            "",
            "Home Assistant before 2026.7: add this to `configuration.yaml` instead and "
            "restart Home Assistant:",
            "",
            "```yaml",
            upstream.yaml_block(suggestion).rstrip("\n"),
            "```",
        ]
    if settings.option == "always" and settings.mtls:
        lines += [
            "",
            f"Or set the app option `forwarded_headers` to `auto`: {name} then sees every "
            f"visitor as {source}.",
        ]
    lines += [
        "",
        f'The app\'s web interface (Caddy mTLS, card "{upstream.card_title(settings)}") shows the '
        "details and checks again.",
    ]
    return title, "\n".join(lines)


def hidden_notification(settings: upstream.Settings, state: upstream.State) -> tuple[str, str]:
    """Title and Markdown text of the notification raised when the add-on
    stops passing visitor addresses on at run time (the upstream stopped
    trusting it)."""
    name = upstream.upstream_name(settings)
    name_start = upstream.upstream_name(settings, start=True)
    source = state.source_address or "this add-on"
    suggestion = upstream.trusted_proxy_suggestion(state.source_address)
    title = (
        "Caddy mTLS: Home Assistant no longer trusts the app - visitor addresses are hidden"
        if settings.is_home_assistant
        else "Caddy mTLS: the upstream no longer trusts the app - visitor addresses are hidden"
    )
    why = (
        " - it restarted without the reverse-proxy settings (Home Assistant also restores "
        "the previous HTTP settings when a change is not confirmed within 5 minutes)"
        if settings.is_home_assistant
        else ""
    )
    lines = [
        f"{name_start} no longer accepts the visitor addresses from this add-on ({source}){why}. "
        f"So that **{settings.domain}** keeps working, the add-on now removes them "
        f"(`forwarded_headers: auto`): {name} sees every visitor as {source}.",
        "",
        "What this means:",
    ]
    lines += [f"- {item}" for item in upstream.strip_consequences(settings, state.source_address)]
    lines += ["", "To pass the visitor addresses on again:"]
    lines += [f"{n}. {step}" for n, step in enumerate(upstream.fix_steps(settings, suggestion), 1)]
    lines += [
        "",
        "The add-on notices the restart and passes the addresses on again by itself; this "
        "notification then disappears. "
        f'The app\'s web interface (Caddy mTLS, card "{upstream.card_title(settings)}") shows the '
        "details.",
    ]
    return title, "\n".join(lines)


_CARD_LOG = {
    "accepted": (logging.INFO, "{Name} accepts this add-on ({source}) as a reverse proxy: visitor "
                 "addresses are passed on (mode pass)."),
    "strip": (logging.WARNING, "{Name} does not trust this add-on ({source}) as a reverse proxy: the "
              "forwarding headers are removed (mode strip), and {name} sees every visitor as {source}."),
    "broken": (logging.WARNING, "{Name} answers every request with 400 Bad Request: it does not trust "
               'this add-on ({source}) as a reverse proxy (see the card "{title}" in the web interface).'),
    "never": (logging.INFO, "forwarded_headers: never - visitor addresses are not passed on."),
    "unreachable": (logging.WARNING, "{Name} {down} ({down_detail}): {effect}."),
    "too_slow": (logging.WARNING, "{Name} answers the test request too slowly to decide whether it trusts "
                 "this add-on ({slow_tests} tests in a row without an answer in time). The add-on stops "
                 "retrying until {name} restarts, the add-on starts or Check again is selected; forwarding "
                 "headers meanwhile: mode {running}."),
    "reload_failed": (logging.ERROR, "Applying the forwarding mode {mode} failed: Caddy could not be "
                      "reloaded ({reload_error}). Caddy keeps mode {running}{broken}; the add-on "
                      "retries every {interval:g} s."),
}


class UpstreamWatch:
    """The monitor's side of upstream.py.

    * Requests: the control request on the kept-alive channel every
      UPSTREAM_CONTROL_INTERVAL seconds in every state (a restart of the
      upstream - the moment trust appears or disappears - is noticed at the
      next one), every UPSTREAM_FAST_INTERVAL seconds while it is
      unreachable, nothing has been decided for it, it is restarting (it
      closed the kept connection and has not answered since) or a test is
      owed - so the window of 400s after it is back stays short - but only
      for the first UPSTREAM_FAST_WINDOW seconds without an answer (the
      period starts anew when it answers; at the start it begins with the
      first look). Not after a test request without an answer in time
      (upstream.SLOW_TESTS_MAX: none until the next event). Under auto in
      mode pass also the periodic test every UPSTREAM_TEST_INTERVAL seconds.
      After a failed reload: a retry instead.
    * Log: one line per change of the card state (and of the reload error).
    * Notifications: "refuses" while every request is answered 400 (from
      the mode Caddy really runs); "addresses hidden" after a switch to
      strip at run time because the upstream stopped trusting the add-on
      (not at a first decision). Each is raised once, dismissed when it is
      over and dismissed once after a start (a previous run's)."""

    def __init__(self, started: float, reload: upstream.Reload | None = upstream.caddy_reload) -> None:
        self.reload = reload
        self.channel: upstream.ControlChannel | None = None
        self.card: str | None = None
        self.logged_error = ""
        self.next_test = started + UPSTREAM_TEST_INTERVAL
        self._raised = False
        self._dismiss_pending = True
        self._hidden_raised = False
        self._hidden_dismiss_pending = True
        #: Since when the control request has not been answered (None: it
        #: was answered at the last look).
        self.down_since: float | None = None

    def tick(self, now: float) -> float:
        """One look; returns the seconds until the next one."""
        settings = upstream.Settings.load()
        if settings is None:
            return UPSTREAM_CONTROL_INTERVAL
        if self.channel is None or self.channel.settings != settings:
            if self.channel is not None:
                self.channel.close()
            self.channel = upstream.ControlChannel(settings, interval=UPSTREAM_CONTROL_INTERVAL)
        state = upstream.load_state(settings)
        if state is not None and not state.applied:
            outcome = upstream.retry_apply(settings, reload=self.reload)
        else:
            force = self._periodic(settings, state) and now >= self.next_test
            outcome = upstream.watch_once(settings, self.channel, reload=self.reload, force_test=force)
            if outcome.tested or not self._periodic(settings, outcome.state):
                self.next_test = now + UPSTREAM_TEST_INTERVAL
        self._report(settings, outcome)
        if outcome.answered:
            self.down_since = None
        elif outcome.answered is False and self.down_since is None:
            self.down_since = now
        st = outcome.state
        # A test owed (nothing decided yet, or it came back) - unless the last
        # test request got no answer in time: then the next one comes at the
        # normal interval (B2-3).
        owed = st.slow_tests == 0 and (st.test_due or (st.decisive is None and st.reachable is not True))
        in_window = self.down_since is None or now - self.down_since < UPSTREAM_FAST_WINDOW
        if st.applied and in_window and (st.reachable is False or owed or self.channel.restart_pending):
            # Down, restarting or a test owed: ask every few seconds, so that
            # the 400s after it is back (trust gone, or nothing decided yet)
            # stay few. A merely slow answer does not count here; after
            # UPSTREAM_FAST_WINDOW seconds without an answer the normal
            # interval.
            return UPSTREAM_FAST_INTERVAL
        if self._periodic(settings, st):
            return max(0.5, min(UPSTREAM_CONTROL_INTERVAL, self.next_test - now))
        return UPSTREAM_CONTROL_INTERVAL

    @staticmethod
    def _periodic(settings: upstream.Settings, state: upstream.State | None) -> bool:
        return (
            settings.option == "auto"
            and state is not None
            and state.reachable is True
            and state.decisive == upstream.ACCEPTED
            and state.running_mode == upstream.PASS
            and state.applied
        )

    def _report(self, settings: upstream.Settings, outcome: upstream.Outcome) -> None:
        state = outcome.state
        if outcome.switched:
            LOG.warning(
                "Forwarding headers: mode %s -> %s (%s answered the test request with %s).",
                outcome.previous_mode,
                state.running_mode,
                settings.target,
                state.test_status if state.test_status is not None else "-",
            )
        if self.card is None:
            self.card = outcome.previous_card
        if outcome.card != self.card or state.reload_error != self.logged_error:
            if outcome.card == upstream.RELOAD_FAILED or outcome.card != self.card:
                level, text = _CARD_LOG.get(outcome.card, (logging.INFO, "Connection to {target}: {card}."))
                down, down_detail = upstream.unreachable_reason(state)
                LOG.log(level, text.format(
                    Name=upstream.upstream_name(settings, start=True),
                    name=upstream.upstream_name(settings),
                    title=upstream.card_title(settings),
                    source=state.source_address or "this add-on", target=settings.target,
                    down=down, down_detail=down_detail, slow_tests=state.slow_tests,
                    effect=upstream.unreachable_effect(state.error_kind),
                    card=outcome.card, mode=state.mode, running=state.running_mode,
                    reload_error=state.reload_error or "-", interval=UPSTREAM_CONTROL_INTERVAL,
                    broken=(" - every request is answered 400" if upstream.is_broken(settings, state) else ""),
                ))
            if self.logged_error and not state.reload_error:
                LOG.info("Caddy reloaded: the forwarding mode %s applies now.", state.running_mode)
            self.card = outcome.card
            self.logged_error = state.reload_error
        if upstream.is_broken(settings, state):
            self._dismiss_pending = False
            if not self._raised:
                title, message = upstream_notification(settings, state)
                self._raised = _send_notification(title, message, UPSTREAM_NOTIFICATION_ID)
        elif state.reachable is True and (self._raised or self._dismiss_pending):
            if _dismiss_notification(UPSTREAM_NOTIFICATION_ID):
                self._raised = False
                self._dismiss_pending = False
        if upstream.is_hidden(state):
            self._hidden_dismiss_pending = False
            if not self._hidden_raised:
                title, message = hidden_notification(settings, state)
                self._hidden_raised = _send_notification(title, message, UPSTREAM_HIDDEN_NOTIFICATION_ID)
        elif self._hidden_raised or self._hidden_dismiss_pending:
            if _dismiss_notification(UPSTREAM_HIDDEN_NOTIFICATION_ID):
                self._hidden_raised = False
                self._hidden_dismiss_pending = False


def main() -> None:
    LOG.info(
        "cert-monitor starting (interval=%ds thresholds=%s state=%s)",
        INTERVAL_SECONDS,
        THRESHOLDS,
        STATE_FILE,
    )
    started = time.monotonic()
    watch = PublicCertWatch(started)
    upstream_watch = UpstreamWatch(started)
    # On startup, Home Assistant Core may not yet be ready (Supervisor
    # returns 502 Bad Gateway while HA boots). Retry quickly with
    # exponential backoff until the first publication succeeds, instead
    # of waiting a full INTERVAL_SECONDS (6h by default).
    backoff = 5
    max_backoff = 300
    initial_done = False
    retry_logged = False
    next_expiry = next_public = next_upstream = started
    while True:
        now = time.monotonic()
        if now >= next_expiry:
            try:
                published = _process_once()
            except Exception as exc:  # noqa: BLE001 - never crash the loop
                LOG.exception("cert-monitor iteration failed: %s", exc)
                published = False
            if initial_done:
                next_expiry = now + INTERVAL_SECONDS
            elif published:
                LOG.info("Initial publication to Home Assistant succeeded.")
                initial_done = True
                next_expiry = now + INTERVAL_SECONDS
            else:
                # Logged once; outside Supervisor this never succeeds.
                LOG.log(
                    logging.DEBUG if retry_logged else logging.INFO,
                    "Initial publication did not reach Home Assistant yet "
                    "(retrying in %ds)...",
                    backoff,
                )
                retry_logged = True
                next_expiry = now + backoff
                backoff = min(backoff * 2, max_backoff)
        if now >= next_public:
            try:
                watch.check(now, public_cert.current_status())
            except Exception as exc:  # noqa: BLE001 - never crash the loop
                LOG.exception("public certificate check failed: %s", exc)
            next_public = now + watch.interval(now)
        if now >= next_upstream:
            try:
                next_upstream = now + upstream_watch.tick(now)
            except Exception as exc:  # noqa: BLE001 - never crash the loop
                LOG.exception("upstream check failed: %s", exc)
                next_upstream = now + UPSTREAM_CONTROL_INTERVAL
        time.sleep(max(0.5, min(next_expiry, next_public, next_upstream) - time.monotonic()))


if __name__ == "__main__":
    main()
