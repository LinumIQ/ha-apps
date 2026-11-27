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
UPSTREAM_CONTROL_INTERVAL seconds on a kept-alive connection; when the
upstream answers again after it was unreachable or restarted, the test
request (does it accept forwarded requests?), which switches the forwarding
mode at run time. Under forwarded_headers: auto in mode pass the test runs
every UPSTREAM_TEST_INTERVAL seconds instead (Home Assistant logs nothing
while it trusts the add-on). While every request is answered "400: Bad
Request" (refused, mode pass) a persistent notification is raised; it is
dismissed when that is over.

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
# request's interval in mode pass under auto, the notification of the state
# "every request is answered 400". (Overridable for tests only.)
UPSTREAM_CONTROL_INTERVAL = float(os.environ.get("CADDY_MTLS_UPSTREAM_CONTROL_SECONDS", "12"))
UPSTREAM_TEST_INTERVAL = float(os.environ.get("CADDY_MTLS_UPSTREAM_TEST_SECONDS", "60"))
UPSTREAM_NOTIFICATION_ID = "caddy_mtls_upstream_refuses"

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
        if settings.option == "always"
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
        "The app's web interface (Caddy mTLS, card \"Home Assistant connection\") shows the "
        "details and checks again.",
    ]
    return title, "\n".join(lines)


_CARD_LOG = {
    "accepted": (logging.INFO, "{name} accepts this add-on ({source}) as a reverse proxy: visitor addresses are passed on (mode pass)."),
    "strip": (logging.WARNING, "{name} does not trust this add-on ({source}) as a reverse proxy: the forwarding headers are removed (mode strip), {name} sees every visitor as {source}."),
    "broken": (logging.WARNING, "{name} answers every request with 400 Bad Request: it does not trust this add-on ({source}) as a reverse proxy (see the web interface)."),
    "never": (logging.INFO, "forwarded_headers: never - visitor addresses are not passed on."),
    "unreachable": (logging.WARNING, "The upstream {target} does not answer ({error}): visitors get 502 Bad Gateway."),
}


class UpstreamWatch:
    """The monitor's side of upstream.py: picks the request (control on the
    kept-alive channel, or the periodic test under auto in mode pass), logs
    one line per change of the card state, raises the notification while
    every request is answered 400 (refused, mode pass) and dismisses it when
    that is over (also once after a start, for a notification of a previous
    run)."""

    def __init__(self, started: float, reload: upstream.Reload | None = upstream.caddy_reload) -> None:
        self.reload = reload
        self.channel: upstream.ControlChannel | None = None
        self.card: str | None = None
        self.next_test = started + UPSTREAM_TEST_INTERVAL
        self._raised = False
        self._dismiss_pending = True

    def tick(self, now: float) -> float:
        """One look; returns the seconds until the next one."""
        settings = upstream.Settings.load()
        if settings is None:
            return UPSTREAM_CONTROL_INTERVAL
        if self.channel is None or self.channel.settings != settings:
            if self.channel is not None:
                self.channel.close()
            self.channel = upstream.ControlChannel(settings)
        state = upstream.load_state(settings)
        if state is not None and not state.applied:
            outcome = upstream.retry_apply(settings, reload=self.reload)
        elif self._periodic(settings, state):
            # The kept-alive connection would idle; a test request every
            # minute watches the upstream (and logs nothing in Home
            # Assistant while it trusts the add-on).
            self.channel.close()
            if now < self.next_test:
                return self.next_test - now
            outcome = upstream.check(settings, test=True, reload=self.reload)
            self.next_test = now + UPSTREAM_TEST_INTERVAL
        else:
            outcome = upstream.watch_once(settings, self.channel, reload=self.reload)
            self.next_test = now + UPSTREAM_TEST_INTERVAL
        self._report(settings, outcome)
        if self._periodic(settings, outcome.state):
            return max(1.0, self.next_test - now)
        return UPSTREAM_CONTROL_INTERVAL

    @staticmethod
    def _periodic(settings: upstream.Settings, state: upstream.State | None) -> bool:
        return (
            settings.option == "auto"
            and state is not None
            and state.reachable is True
            and state.decisive == upstream.ACCEPTED
            and state.mode == upstream.PASS
            and state.applied
        )

    def _report(self, settings: upstream.Settings, outcome: upstream.Outcome) -> None:
        state = outcome.state
        if outcome.switched:
            LOG.warning(
                "Forwarding headers: mode %s -> %s (%s answered the test request with %s).",
                outcome.previous_mode,
                state.mode,
                settings.target,
                state.test_status if state.test_status is not None else "-",
            )
        if outcome.reload_error:
            LOG.error("Reloading Caddy for the forwarding mode failed (retried): %s", outcome.reload_error)
        if self.card is None:
            self.card = outcome.previous_card
        if outcome.card != self.card:
            level, text = _CARD_LOG.get(outcome.card, (logging.INFO, "Connection to {target}: {card}."))
            name = upstream.upstream_name(settings)
            LOG.log(level, text.format(
                name=name[:1].upper() + name[1:],
                source=state.source_address or "this add-on", target=settings.target,
                error=state.error or "no answer", card=outcome.card,
            ))
            self.card = outcome.card
        if outcome.card == "broken":
            self._dismiss_pending = False
            if not self._raised:
                title, message = upstream_notification(settings, state)
                self._raised = _send_notification(title, message, UPSTREAM_NOTIFICATION_ID)
        elif outcome.card in ("accepted", "strip", "never") and (self._raised or self._dismiss_pending):
            if _dismiss_notification(UPSTREAM_NOTIFICATION_ID):
                self._raised = False
                self._dismiss_pending = False


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
