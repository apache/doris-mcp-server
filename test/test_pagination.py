"""Unit tests for core.pagination (offline, in-memory TTL cache).

Covers:
  - First page / follow-up pages via page token
  - total_count and next_page_token semantics
  - page_size <= 0 falls back to default (50)
  - Unknown token silently falls back to page 1 (known behaviour)
  - Expired token silently falls back to page 1 (known behaviour)
  - Consumed tokens are single-use (deleted after use)
"""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from core import pagination  # noqa: E402
from core.pagination import paginate  # noqa: E402


class TestPaginate(unittest.TestCase):
    def setUp(self):
        # _cache is module-level state — isolate every test.
        pagination._cache.clear()

    def test_first_page_returns_token_and_total(self):
        page, token, total = paginate(list(range(10)), page_size=3)
        self.assertEqual(page, [0, 1, 2])
        self.assertIsNotNone(token)
        self.assertEqual(total, 10)

    def test_second_page_via_token(self):
        items = list(range(10))
        _, token, _ = paginate(items, page_size=3)
        page, token2, total = paginate(items, page_size=3, page_token=token)
        self.assertEqual(page, [3, 4, 5])
        self.assertIsNotNone(token2)
        self.assertEqual(total, 10)

    def test_last_page_has_no_next_token(self):
        items = list(range(6))
        _, token, _ = paginate(items, page_size=3)
        page, token2, total = paginate(items, page_size=3, page_token=token)
        self.assertEqual(page, [3, 4, 5])
        self.assertIsNone(token2)
        self.assertEqual(total, 6)

    def test_exact_fit_single_page_has_no_token(self):
        page, token, total = paginate(list(range(3)), page_size=3)
        self.assertEqual(page, [0, 1, 2])
        self.assertIsNone(token)
        self.assertEqual(total, 3)

    def test_non_positive_page_size_falls_back_to_default(self):
        items = list(range(60))
        page, token, _ = paginate(items, page_size=0)
        self.assertEqual(len(page), 50)  # default page_size
        self.assertIsNotNone(token)

    def test_token_is_single_use(self):
        """Used tokens are removed from the cache, so reusing one is
        treated like an unknown token and returns page 1 (known behaviour:
        no error is raised, the caller silently restarts)."""
        items = list(range(10))
        _, token, _ = paginate(items, page_size=3)
        paginate(items, page_size=3, page_token=token)  # consumes the token
        self.assertNotIn(token, pagination._cache)
        page, _, _ = paginate(items, page_size=3, page_token=token)
        self.assertEqual(page, [0, 1, 2])

    def test_unknown_token_falls_back_to_first_page(self):
        # Known behaviour: an unrecognized token does not raise — the
        # caller silently gets page 1 of the fresh item list.
        page, _, total = paginate(list(range(10)), page_size=3, page_token="nope:6")
        self.assertEqual(page, [0, 1, 2])
        self.assertEqual(total, 10)

    def test_expired_token_falls_back_to_first_page(self):
        """Known behaviour: expired tokens are cleaned up lazily and the
        caller silently gets page 1 instead of an error."""
        items = list(range(10))
        _, token, _ = paginate(items, page_size=3)
        # Age the cached entry beyond the TTL
        cached_items, _ = pagination._cache[token]
        pagination._cache[token] = (cached_items, time.time() - pagination._TTL - 1)
        page, token2, _ = paginate(items, page_size=3, page_token=token)
        self.assertEqual(page, [0, 1, 2])
        self.assertIsNotNone(token2)  # a fresh walk starts over

    def test_unexpired_token_survives_cleanup(self):
        items = list(range(10))
        _, token, _ = paginate(items, page_size=3)
        page, _, _ = paginate(items, page_size=3, page_token=token)
        self.assertEqual(page, [3, 4, 5])


if __name__ == "__main__":
    unittest.main(verbosity=2)
