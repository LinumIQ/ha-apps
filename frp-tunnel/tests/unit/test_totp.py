"""RFC 6238 test vectors for the E2E harness's stdlib TOTP implementation."""
from __future__ import annotations

import base64
import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "e2e"))

import approve  # noqa: E402

# RFC 6238 appendix B (SHA-1 seed "12345678901234567890", 8 digits).
SECRET = base64.b32encode(b"12345678901234567890").decode()
VECTORS = {
    59: "94287082",
    1111111109: "07081804",
    1111111111: "14050471",
    1234567890: "89005924",
    2000000000: "69279037",
    20000000000: "65353130",
}


class TotpTests(unittest.TestCase):
    def test_rfc6238_sha1_vectors(self):
        for at, code in VECTORS.items():
            self.assertEqual(approve.totp(SECRET, at=at, digits=8, digest=hashlib.sha1), code, at)

    def test_six_digits_and_lenient_secret_format(self):
        code = approve.totp(SECRET, at=59)
        self.assertEqual(code, "287082")
        spaced = " ".join(SECRET[i:i + 4] for i in range(0, len(SECRET), 4)).lower()
        self.assertEqual(approve.totp(spaced.rstrip("="), at=59), code)

    def test_session_cookie_matches_supabase_ssr_format(self):
        session = {"access_token": "a" * 5000, "refresh_token": "r"}
        cookies = approve.session_cookies("sb-api-dev-auth-token", session)
        self.assertGreater(len(cookies), 1)
        self.assertEqual(cookies[0][0], "sb-api-dev-auth-token.0")
        joined = "".join(v for _, v in cookies)
        self.assertTrue(joined.startswith("base64-"))
        raw = joined[len("base64-"):]
        decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        self.assertEqual(decoded, b'{"access_token":"' + b"a" * 5000 + b'","refresh_token":"r"}')
        small = approve.session_cookies("n", {"a": 1})
        self.assertEqual([k for k, _ in small], ["n"])


if __name__ == "__main__":
    unittest.main()
