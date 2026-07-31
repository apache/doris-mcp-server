"""Unit tests for core.sensitive_mask (offline, pure functions).

Only asserts stable, long-standing behaviour:
  - password=/passwd= values are masked
  - sk- tokens are masked
  - ordinary text is left untouched
  - mask_dict masks sensitive keys recursively

NOTE: pattern coverage may be extended in parallel work; do not assert
patterns beyond the ones above.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from core.sensitive_mask import (  # noqa: E402
    mask_dict,
    mask_password,
    mask_sensitive,
    mask_token,
)


class TestMaskPassword(unittest.TestCase):
    def test_password_equals_masked(self):
        self.assertEqual(mask_password("password=secret123"), "password=****")

    def test_password_colon_masked(self):
        self.assertEqual(mask_password("password: secret123"), "password: ****")

    def test_password_case_insensitive(self):
        self.assertEqual(mask_password("PASSWORD=secret123"), "PASSWORD=****")

    def test_passwd_masked(self):
        self.assertEqual(mask_password("passwd=hunter2"), "passwd=****")

    def test_password_inside_longer_text(self):
        result = mask_password("connect failed: user=admin password=p@ss retry")
        self.assertIn("password=****", result)
        self.assertNotIn("p@ss", result)

    def test_normal_text_unchanged(self):
        text = "SELECT * FROM orders WHERE status = 'done'"
        self.assertEqual(mask_password(text), text)

    def test_empty_string(self):
        self.assertEqual(mask_password(""), "")


class TestMaskToken(unittest.TestCase):
    def test_sk_token_masked(self):
        self.assertEqual(mask_token("token sk-abc123XYZ_-9 here"), "token **** here")

    def test_normal_text_unchanged(self):
        text = "no tokens in this message"
        self.assertEqual(mask_token(text), text)


class TestMaskSensitive(unittest.TestCase):
    def test_masks_both_password_and_token(self):
        result = mask_sensitive("password=pw1 key=sk-abc123")
        self.assertEqual(result, "password=**** key=****")

    def test_normal_text_unchanged(self):
        text = "ordinary log line, nothing sensitive"
        self.assertEqual(mask_sensitive(text), text)


class TestMaskDict(unittest.TestCase):
    def test_sensitive_keys_masked(self):
        d = {"user": "admin", "password": "secret123"}
        result = mask_dict(d)
        self.assertEqual(result["password"], "****")
        self.assertEqual(result["user"], "admin")

    def test_nested_dict_masked(self):
        d = {"conn": {"host": "127.0.0.1", "password": "secret123"}}
        result = mask_dict(d)
        self.assertEqual(result["conn"]["password"], "****")
        self.assertEqual(result["conn"]["host"], "127.0.0.1")

    def test_string_values_scrubbed(self):
        d = {"msg": "login failed for password=secret123"}
        result = mask_dict(d)
        self.assertEqual(result["msg"], "login failed for password=****")

    def test_non_sensitive_values_untouched(self):
        d = {"count": 42, "ok": True, "name": "orders"}
        self.assertEqual(mask_dict(d), d)


if __name__ == "__main__":
    unittest.main(verbosity=2)
