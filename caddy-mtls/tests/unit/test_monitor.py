"""Unit tests for cert-mgr/monitor.py (the certificate expiry monitor).

Standard library only. Runs against the repository's monitor.py, or against
the installed one with CERT_MGR_DIR, e.g. inside the built image:

    python -m unittest discover -s caddy-mtls/tests/unit -v

    docker run --rm -v "$PWD/caddy-mtls/tests:/tests:ro" \
        -e CERT_MGR_DIR=/usr/lib/cert-mgr --entrypoint python3 caddy-mtls-test \
        -m unittest discover -s /tests/unit -v
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

CERT_MGR = Path(
    os.environ.get("CERT_MGR_DIR")
    or Path(__file__).resolve().parents[2] / "rootfs" / "usr" / "lib" / "cert-mgr"
)
sys.path.insert(0, str(CERT_MGR))

import monitor  # noqa: E402

#: Home Assistant core's entity id rule (homeassistant/core.py,
#: VALID_ENTITY_ID): POST /api/states/<entity_id> answers 400 "Invalid entity
#: ID specified." for anything else.
VALID_ENTITY_ID = re.compile(r"^(?!.+__)(?!_)[\da-z_]+(?<!_)\.(?!_)[\da-z_]+(?<!_)$")


def client_entity_id(slug: str) -> str:
    return f"sensor.caddy_mtls_client_{slug}_expiry"


class EntitySlugTest(unittest.TestCase):
    def test_examples(self) -> None:
        cases = {
            "user": "user",
            "alice-phone": "alice_phone",
            "john.laptop": "john_laptop",
            "mary_tablet": "mary_tablet",
            "Mary-Tablet": "mary_tablet",
            "x_": "x",
            "_x": "x",
            "a__b": "a_b",
            "a.-_b": "a_b",
            "-lead.trail-": "lead_trail",
            "R2-D2.2026": "r2_d2_2026",
            "ÄÖÜ-tablet": "tablet",
            "_": "",
            "--": "",
        }
        for name, slug in cases.items():
            with self.subTest(name=name):
                self.assertEqual(monitor.entity_slug(name), slug)

    def test_entity_ids_are_valid_for_home_assistant(self) -> None:
        names = [
            "user", "alice-phone", "john.laptop", "x_", "_x", "a__b", "-", "_",
            "--", "..", "a" * 64, "Z9", "ÄÖÜ", "é", "K", "x" + "-" * 30 + "y",
            "alice.phone", "alice_phone", "Alice-Phone",
        ]
        slugs = monitor.client_entity_slugs(names)
        self.assertEqual(set(slugs), set(names))
        for name in names:
            with self.subTest(name=name):
                self.assertRegex(client_entity_id(slugs[name]), VALID_ENTITY_ID)
        # The CA's sensor id as well.
        self.assertRegex("sensor.caddy_mtls_ca_expiry", VALID_ENTITY_ID)

    def test_the_raw_names_of_the_review_fail_without_a_slug(self) -> None:
        # The bug (review 2026-10-27 M6): the raw name in the entity id.
        for name in ("alice-phone", "john.laptop", "x_"):
            with self.subTest(name=name):
                self.assertNotRegex(client_entity_id(name), VALID_ENTITY_ID)


class ClientEntitySlugsTest(unittest.TestCase):
    def test_unique_slugs_on_collision(self) -> None:
        names = ["alice.phone", "alice-phone", "alice_phone", "Alice-Phone"]
        slugs = monitor.client_entity_slugs(names)
        self.assertEqual(len(set(slugs.values())), len(names))
        self.assertEqual(slugs["alice.phone"], "alice_phone")  # first one: plain
        for name in names[1:]:
            with self.subTest(name=name):
                self.assertRegex(slugs[name], r"^alice_phone_[0-9a-f]{6}$")

    def test_deterministic_and_stable_when_names_are_added(self) -> None:
        names = ["alice-phone", "bob", "alice.phone"]
        first = monitor.client_entity_slugs(names)
        self.assertEqual(first, monitor.client_entity_slugs(names))
        later = monitor.client_entity_slugs(names + ["alice_phone", "carol"])
        for name in names:
            with self.subTest(name=name):
                self.assertEqual(later[name], first[name])

    def test_names_without_letters_or_digits(self) -> None:
        slugs = monitor.client_entity_slugs(["_", "-", "--", "."])
        self.assertEqual(len(set(slugs.values())), 4)
        for name, slug in slugs.items():
            with self.subTest(name=name):
                self.assertRegex(slug, r"^[0-9a-f]{6,}$")
                self.assertRegex(client_entity_id(slug), VALID_ENTITY_ID)

    def test_hash_slug_taken_by_another_name(self) -> None:
        # A later name whose plain slug equals an earlier generated one.
        taken = monitor.client_entity_slugs(["alice.phone", "alice-phone"])["alice-phone"]
        slugs = monitor.client_entity_slugs(["alice.phone", "alice-phone", taken])
        self.assertEqual(len(set(slugs.values())), 3)

    def test_duplicate_names_share_one_slug(self) -> None:
        self.assertEqual(monitor.client_entity_slugs(["bob", "bob"]), {"bob": "bob"})


class CrossedThresholdTest(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.object(monitor, "THRESHOLDS", [30, 14, 7, 1])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_thresholds(self) -> None:
        # (days_left, last_notified) -> threshold to notify for (or None)
        cases = [
            ((400, None), None),
            ((31, None), None),
            ((30, None), 30),
            ((20, None), 30),
            ((20, 30), None),
            ((14, 30), 14),
            ((10, None), 14),
            ((10, 14), None),
            ((5, 30), 7),
            ((1, 7), 1),
            ((0, None), 1),
            ((-3, 1), None),
            ((-3, None), 1),
            ((25, 14), None),
        ]
        for (days_left, last), expected in cases:
            with self.subTest(days_left=days_left, last=last):
                self.assertEqual(monitor._crossed_threshold(days_left, last), expected)

    def test_custom_thresholds(self) -> None:
        with mock.patch.object(monitor, "THRESHOLDS", [60]):
            self.assertEqual(monitor._crossed_threshold(59, None), 60)
            self.assertIsNone(monitor._crossed_threshold(59, 60))
            self.assertIsNone(monitor._crossed_threshold(61, None))


def iso(days: float) -> str:
    when = datetime.now(timezone.utc) + timedelta(days=days)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


class ProcessOnceTest(unittest.TestCase):
    """_process_once publishes one valid entity per active certificate."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state_file = Path(tmp.name) / "state.json"
        self.notified_file = Path(tmp.name) / "notified.json"
        for name, value in (
            ("STATE_FILE", self.state_file),
            ("NOTIFIED_FILE", self.notified_file),
            ("THRESHOLDS", [30, 14, 7, 1]),
        ):
            patcher = mock.patch.object(monitor, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.calls: list[tuple[str, str, dict]] = []

        def fake_request(method: str, path: str, payload: dict | None = None) -> bool:
            self.calls.append((method, path, payload or {}))
            return True

        patcher = mock.patch.object(monitor, "_supervisor_request", side_effect=fake_request)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_state(self, clients: list[dict]) -> None:
        state = {
            "version": 1,
            "ca": {"serial": "CA01", "not_after": iso(36500)},
            "clients": clients,
        }
        self.state_file.write_text(json.dumps(state))

    def test_sensors_and_notifications(self) -> None:
        self.write_state([
            {"name": "alice-phone", "status": "active", "serial": "A1", "not_after": iso(10.5)},
            {"name": "john.laptop", "status": "active", "serial": "B2", "not_after": iso(400)},
            {"name": "bob", "status": "revoked", "serial": "C3", "not_after": iso(400)},
            {"name": "alice_phone", "status": "active", "serial": "D4", "not_after": iso(400)},
        ])
        self.assertTrue(monitor._process_once())

        sensors = {
            path.rsplit("/", 1)[1]: payload
            for method, path, payload in self.calls
            if method == "POST" and path.startswith("/core/api/states/")
        }
        for entity_id in sensors:
            with self.subTest(entity_id=entity_id):
                self.assertRegex(entity_id, VALID_ENTITY_ID)
        self.assertIn("sensor.caddy_mtls_ca_expiry", sensors)
        self.assertIn("sensor.caddy_mtls_client_alice_phone_expiry", sensors)
        self.assertIn("sensor.caddy_mtls_client_john_laptop_expiry", sensors)
        self.assertEqual(len(sensors), 4)  # CA + 3 active clients (bob is revoked)
        friendly = {p["attributes"]["friendly_name"] for p in sensors.values()}
        self.assertIn("Caddy mTLS client alice-phone expiry", friendly)
        self.assertIn("Caddy mTLS client alice_phone expiry", friendly)
        self.assertIn("Caddy mTLS client john.laptop expiry", friendly)
        self.assertFalse(any("bob" in entity_id for entity_id in sensors))

        notifications = [
            payload for method, path, payload in self.calls
            if path == "/core/api/services/persistent_notification/create"
        ]
        self.assertEqual(len(notifications), 1)  # alice-phone: 10 days -> 14
        self.assertEqual(
            notifications[0]["notification_id"], "caddy_mtls_client_alice_phone_expiry"
        )
        self.assertIn("alice-phone", notifications[0]["title"])
        self.assertEqual(
            json.loads(self.notified_file.read_text()), {"client_alice-phone:A1": 14}
        )

        # Second run: same state -> no new notification.
        self.calls.clear()
        monitor._process_once()
        self.assertFalse(any("persistent_notification" in path for _, path, _ in self.calls))


if __name__ == "__main__":
    unittest.main()
