"""
test_nvd_api_collector.py
--------------------------
Tests for get_date_range, parse_cve_data, fetch_cves (403 retry limit).
"""

import pytest
from unittest.mock import MagicMock, patch

from scripts.nvd_api_collector import get_date_range, parse_cve_data, fetch_cves


# ── get_date_range ──────────────────────────────────────────────────────────────

class TestGetDateRange:
    def test_returns_two_strings(self):
        start, end = get_date_range(7)
        assert isinstance(start, str)
        assert isinstance(end, str)

    def test_format_matches_nvd_spec(self):
        """NVD expects: YYYY-MM-DDTHH:MM:SS.mmmZ"""
        start, end = get_date_range(7)
        import re
        pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z"
        assert re.match(pattern, start)
        assert re.match(pattern, end)

    def test_start_is_before_end(self):
        start, end = get_date_range(7)
        assert start < end

    def test_days_offset_is_correct(self):
        from datetime import datetime, timezone, timedelta
        start_str, end_str = get_date_range(7)
        start = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
        end = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
        diff = end - start
        assert 6 <= diff.days <= 7


# ── parse_cve_data ──────────────────────────────────────────────────────────────

class TestParseCveData:
    def _full_cve(self):
        return {
            "id": "CVE-2024-12345",
            "published": "2024-01-15T00:00:00.000Z",
            "lastModified": "2024-01-16T00:00:00.000Z",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "A critical buffer overflow."}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    }
                }]
            },
            "weaknesses": [{"description": [{"value": "CWE-119"}]}],
            "references": [{"url": "https://example.com/advisory", "source": "vendor", "tags": ["Patch"]}],
            "configurations": [],
        }

    def test_url_contains_cve_id(self):
        row = parse_cve_data(self._full_cve())
        assert "CVE-2024-12345" in row["url"]
        assert "nvd.nist.gov" in row["url"]

    def test_title_contains_cve_id(self):
        row = parse_cve_data(self._full_cve())
        assert "CVE-2024-12345" in row["title"]

    def test_title_contains_severity_when_available(self):
        row = parse_cve_data(self._full_cve())
        assert "CRITICAL" in row["title"]

    def test_source_feed_is_nvd_api(self):
        row = parse_cve_data(self._full_cve())
        assert row["source_feed"] == "nvd_api"

    def test_status_is_pending(self):
        row = parse_cve_data(self._full_cve())
        assert row["status"] == "pending"

    def test_raw_content_is_json_string(self):
        import json
        row = parse_cve_data(self._full_cve())
        content = json.loads(row["raw_content"])
        assert content["cve_id"] == "CVE-2024-12345"
        assert content["description"] == "A critical buffer overflow."

    def test_raw_content_includes_cwes(self):
        import json
        row = parse_cve_data(self._full_cve())
        content = json.loads(row["raw_content"])
        assert "CWE-119" in content["cwes"]

    def test_missing_cvss_returns_empty_dict(self):
        import json
        cve = self._full_cve()
        cve["metrics"] = {}
        row = parse_cve_data(cve)
        content = json.loads(row["raw_content"])
        assert content["cvss"] == {}

    def test_missing_description_returns_empty_string(self):
        import json
        cve = self._full_cve()
        cve["descriptions"] = []
        row = parse_cve_data(cve)
        content = json.loads(row["raw_content"])
        assert content["description"] == ""

    def test_published_date_parsed_to_iso(self):
        row = parse_cve_data(self._full_cve())
        assert row["published_at"] is not None
        assert "2024-01-15" in row["published_at"]


# ── fetch_cves (403 retry limit) ────────────────────────────────────────────────

class TestFetchCves:
    def _make_response(self, status_code=200, data=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = data or {"vulnerabilities": [], "totalResults": 0}
        resp.raise_for_status = MagicMock()
        return resp

    def test_returns_empty_list_on_empty_response(self):
        with patch("scripts.nvd_api_collector.requests.get") as mock_get:
            mock_get.return_value = self._make_response(200, {"vulnerabilities": [], "totalResults": 0})
            result = fetch_cves("2024-01-01T00:00:00.000Z", "2024-01-08T00:00:00.000Z")
        assert result == []

    def test_stops_after_max_403_retries(self):
        with patch("scripts.nvd_api_collector.requests.get") as mock_get, \
             patch("scripts.nvd_api_collector.time.sleep"):
            mock_get.return_value = self._make_response(403)
            result = fetch_cves("2024-01-01T00:00:00.000Z", "2024-01-08T00:00:00.000Z")
        # Should return empty list (not raise, not loop forever)
        assert result == []

    def test_does_not_loop_forever_on_403(self):
        call_count = 0
        MAX = 10  # safety ceiling

        def fake_get(*a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count > MAX:
                raise AssertionError("Too many retries — infinite loop detected")
            return self._make_response(403)

        with patch("scripts.nvd_api_collector.requests.get", side_effect=fake_get), \
             patch("scripts.nvd_api_collector.time.sleep"):
            fetch_cves("2024-01-01T00:00:00.000Z", "2024-01-08T00:00:00.000Z")

        assert call_count <= MAX

    def test_paginates_when_more_results_exist(self):
        page1 = {
            "vulnerabilities": [{"cve": {"id": "CVE-2024-0001", "descriptions": [], "metrics": {}, "weaknesses": [], "references": [], "published": ""}}],
            "totalResults": 2,
        }
        page2 = {
            "vulnerabilities": [{"cve": {"id": "CVE-2024-0002", "descriptions": [], "metrics": {}, "weaknesses": [], "references": [], "published": ""}}],
            "totalResults": 2,
        }

        responses = [
            self._make_response(200, page1),
            self._make_response(200, page2),
        ]

        with patch("scripts.nvd_api_collector.requests.get", side_effect=responses), \
             patch("scripts.nvd_api_collector.time.sleep"):
            result = fetch_cves("2024-01-01T00:00:00.000Z", "2024-01-08T00:00:00.000Z")

        assert len(result) == 2
