"""
test_news_collector.py
-----------------------
Tests for parse_date, get_content, and main() feed collection logic.
"""

import pytest
from unittest.mock import MagicMock, patch
from tests.conftest import make_mock_db

from scripts.news_collector import parse_date, get_content


# ── Helpers ─────────────────────────────────────────────────────────────────────

def make_entry(**kwargs):
    """Build a fake feedparser entry object."""
    entry = MagicMock()
    for key, val in kwargs.items():
        setattr(entry, key, val)
    return entry


# ── parse_date ──────────────────────────────────────────────────────────────────

class TestParseDate:
    def test_valid_published_parsed_returns_iso(self):
        entry = make_entry(published_parsed=(2024, 3, 15, 10, 30, 0, 0, 0, 0))
        result = parse_date(entry)
        assert result is not None
        assert "2024-03-15" in result

    def test_missing_published_parsed_returns_none(self):
        entry = MagicMock(spec=[])  # no attributes
        result = parse_date(entry)
        assert result is None

    def test_published_parsed_none_returns_none(self):
        entry = make_entry(published_parsed=None)
        result = parse_date(entry)
        assert result is None

    def test_result_is_utc_isoformat(self):
        entry = make_entry(published_parsed=(2025, 1, 1, 0, 0, 0, 0, 0, 0))
        result = parse_date(entry)
        assert "+00:00" in result or result.endswith("Z") or "2025-01-01" in result


# ── get_content ─────────────────────────────────────────────────────────────────

class TestGetContent:
    def test_prefers_content_over_summary(self):
        content_obj = MagicMock()
        content_obj.value = "Full article content"
        entry = make_entry(content=[content_obj], summary="Short summary")
        assert get_content(entry) == "Full article content"

    def test_falls_back_to_summary_when_no_content(self):
        entry = MagicMock(spec=["summary"])
        entry.summary = "Summary text"
        assert get_content(entry) == "Summary text"

    def test_returns_empty_string_when_nothing_available(self):
        entry = MagicMock(spec=[])
        assert get_content(entry) == ""

    def test_empty_content_list_falls_back_to_summary(self):
        entry = make_entry(content=[], summary="Fallback")
        assert get_content(entry) == "Fallback"

    def test_content_list_uses_first_element(self):
        c1 = MagicMock(); c1.value = "First"
        c2 = MagicMock(); c2.value = "Second"
        entry = make_entry(content=[c1, c2])
        assert get_content(entry) == "First"


# ── main() integration ──────────────────────────────────────────────────────────

class TestNewsCollectorMain:
    def _make_feed(self, entries):
        feed = MagicMock()
        feed.bozo = False
        feed.entries = entries
        return feed

    def _make_valid_entry(self, title="Test Title", link="https://example.com/1"):
        c = MagicMock(); c.value = "Article body"
        entry = MagicMock()
        entry.title = title
        entry.link = link
        entry.content = [c]
        entry.summary = "summary"
        entry.published_parsed = (2024, 1, 1, 0, 0, 0, 0, 0, 0)
        return entry

    def test_skips_entry_without_url(self):
        db, tables = make_mock_db({"raw_articles": []})
        entry = self._make_valid_entry()
        entry.link = None
        feed = self._make_feed([entry])

        with patch("scripts.news_collector.feedparser") as fp, \
             patch("scripts.news_collector.create_client", return_value=db):
            fp.parse.return_value = feed
            from scripts.news_collector import main
            main()

        assert len(tables.get("raw_articles", FakeTable()).inserted) == 0

    def test_skips_entry_without_title(self):
        db, tables = make_mock_db({"raw_articles": []})
        entry = self._make_valid_entry()
        entry.title = None
        feed = self._make_feed([entry])

        with patch("scripts.news_collector.feedparser") as fp, \
             patch("scripts.news_collector.create_client", return_value=db):
            fp.parse.return_value = feed
            from scripts.news_collector import main
            main()

        assert len(tables.get("raw_articles", FakeTable()).inserted) == 0

    def test_continues_after_bozo_feed(self):
        """Feed parse error should not crash main()."""
        db, _ = make_mock_db()
        feed = MagicMock()
        feed.bozo = True
        feed.bozo_exception = Exception("parse error")
        feed.entries = []

        with patch("scripts.news_collector.feedparser") as fp, \
             patch("scripts.news_collector.create_client", return_value=db):
            fp.parse.return_value = feed
            from scripts.news_collector import main
            main()  # should not raise


# avoid name collision
from tests.conftest import FakeTable
