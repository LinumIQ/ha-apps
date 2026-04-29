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

Failure to reach the Supervisor never crashes the loop - we log and try
again on the next iteration.
"""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest

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

# Tracks which (cert_id, threshold_days) pairs we've already notified for
# in the current state, so we don't spam HA on every loop iteration.
NOTIFIED_FILE = Path(
    os.environ.get("CERT_MONITOR_NOTIFIED_FILE", "/data/cert-monitor.notified.json")
)


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


def _publish_sensor(slug: str, friendly: str, days_left: int, not_after: str) -> None:
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
    _supervisor_request("POST", f"/core/api/states/{entity_id}", payload)


def _send_notification(title: str, message: str, notification_id: str) -> None:
    payload = {
        "title": title,
        "message": message,
        "notification_id": notification_id,
    }
    _supervisor_request(
        "POST",
        "/core/api/services/persistent_notification/create",
        payload,
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


def _process_once() -> None:
    state = _read_state()
    if not state:
        return
    notified = _read_notified()

    items: list[tuple[str, str, dict[str, Any]]] = []
    if state.get("ca"):
        items.append(("ca", "CA", state["ca"]))
    for c in state.get("clients", []):
        if c.get("status") == "active":
            items.append((f"client_{c['name']}", f"client {c['name']}", c))

    new_notified = dict(notified)
    for slug, friendly, meta in items:
        days_left = _days_until(meta.get("not_after"))
        if days_left is None:
            continue
        _publish_sensor(slug, friendly, days_left, meta.get("not_after", ""))

        # Identify cert by serial so rotation resets the notification state.
        identity = f"{slug}:{meta.get('serial','')}"
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
    current_ids = {f"{slug}:{meta.get('serial','')}" for slug, _, meta in items}
    new_notified = {k: v for k, v in new_notified.items() if k in current_ids}
    if new_notified != notified:
        _write_notified(new_notified)


def main() -> None:
    LOG.info(
        "cert-monitor starting (interval=%ds thresholds=%s state=%s)",
        INTERVAL_SECONDS,
        THRESHOLDS,
        STATE_FILE,
    )
    while True:
        try:
            _process_once()
        except Exception as exc:  # noqa: BLE001 - never crash the loop
            LOG.exception("cert-monitor iteration failed: %s", exc)
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
