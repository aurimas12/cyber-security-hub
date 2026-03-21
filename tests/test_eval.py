"""
test_eval.py
------------
Tests for MITRE ID format validation, CVE format validation,
fetch_valid_mitre_ids (mock STIX), check_cve_exists (mock NVD API).
"""

import pytest
from unittest.mock import patch, MagicMock

from scripts.eval import mitre_id_format_ok, fetch_valid_mitre_ids, check_cve_exists


# ── mitre_id_format_ok ──────────────────────────────────────────────────────────

class TestMitreIdFormatOk:
    def test_valid_top_level_technique(self):
        assert mitre_id_format_ok("T1566") is True

    def test_valid_sub_technique(self):
        assert mitre_id_format_ok("T1566.001") is True

    def test_valid_four_digit_id(self):
        assert mitre_id_format_ok("T1059") is True

    def test_valid_sub_technique_001(self):
        assert mitre_id_format_ok("T1059.001") is True

    def test_invalid_lowercase_t(self):
        assert mitre_id_format_ok("t1566") is False

    def test_invalid_three_digits(self):
        assert mitre_id_format_ok("T156") is False

    def test_invalid_five_digits(self):
        assert mitre_id_format_ok("T15660") is False

    def test_invalid_sub_technique_too_short(self):
        assert mitre_id_format_ok("T1566.01") is False

    def test_invalid_sub_technique_too_long(self):
        assert mitre_id_format_ok("T1566.0012") is False

    def test_invalid_random_string(self):
        assert mitre_id_format_ok("PowerShell") is False

    def test_invalid_empty_string(self):
        assert mitre_id_format_ok("") is False

    def test_invalid_hallucinated_id(self):
        assert mitre_id_format_ok("T9999.999") is True  # valid FORMAT, may not exist in ATT&CK


# ── CVE ID format (via validate_cve_ids regex) ──────────────────────────────────

class TestCveIdFormat:
    import re
    _pattern = __import__("re").compile(r"CVE-\d{4}-\d{4,7}")

    def test_valid_4_digit_suffix(self):
        assert self._pattern.fullmatch("CVE-2024-1234") is not None

    def test_valid_7_digit_suffix(self):
        assert self._pattern.fullmatch("CVE-2024-1234567") is not None

    def test_invalid_3_digit_suffix(self):
        assert self._pattern.fullmatch("CVE-2024-123") is None

    def test_invalid_no_year(self):
        assert self._pattern.fullmatch("CVE-12345") is None

    def test_invalid_lowercase(self):
        assert self._pattern.fullmatch("cve-2024-1234") is None

    def test_invalid_missing_prefix(self):
        assert self._pattern.fullmatch("2024-1234") is None


# ── fetch_valid_mitre_ids ───────────────────────────────────────────────────────

class TestFetchValidMitreIds:
    def _make_stix_bundle(self, objects):
        return {"objects": objects}

    def _make_technique(self, technique_id, deprecated=False, revoked=False):
        return {
            "type": "attack-pattern",
            "name": f"Technique {technique_id}",
            "x_mitre_deprecated": deprecated,
            "revoked": revoked,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": technique_id}
            ],
        }

    def _mock_response(self, bundle):
        resp = MagicMock()
        resp.json.return_value = bundle
        resp.raise_for_status = MagicMock()
        return resp

    def test_returns_set_of_technique_ids(self):
        bundle = self._make_stix_bundle([self._make_technique("T1566")])
        with patch("scripts.eval.requests.get", return_value=self._mock_response(bundle)):
            result = fetch_valid_mitre_ids()
        assert "T1566" in result

    def test_excludes_deprecated_techniques(self):
        bundle = self._make_stix_bundle([self._make_technique("T1086", deprecated=True)])
        with patch("scripts.eval.requests.get", return_value=self._mock_response(bundle)):
            result = fetch_valid_mitre_ids()
        assert "T1086" not in result

    def test_excludes_revoked_techniques(self):
        bundle = self._make_stix_bundle([self._make_technique("T1500", revoked=True)])
        with patch("scripts.eval.requests.get", return_value=self._mock_response(bundle)):
            result = fetch_valid_mitre_ids()
        assert "T1500" not in result

    def test_ignores_non_attack_pattern_objects(self):
        bundle = self._make_stix_bundle([
            {"type": "malware", "name": "SomeRat", "external_references": [
                {"source_name": "mitre-attack", "external_id": "T9000"}
            ]},
            self._make_technique("T1566"),
        ])
        with patch("scripts.eval.requests.get", return_value=self._mock_response(bundle)):
            result = fetch_valid_mitre_ids()
        assert "T9000" not in result
        assert "T1566" in result

    def test_returns_set_type(self):
        bundle = self._make_stix_bundle([self._make_technique("T1566")])
        with patch("scripts.eval.requests.get", return_value=self._mock_response(bundle)):
            result = fetch_valid_mitre_ids()
        assert isinstance(result, set)

    def test_multiple_techniques_all_included(self):
        techniques = [self._make_technique(f"T100{i}") for i in range(5)]
        bundle = self._make_stix_bundle(techniques)
        with patch("scripts.eval.requests.get", return_value=self._mock_response(bundle)):
            result = fetch_valid_mitre_ids()
        for i in range(5):
            assert f"T100{i}" in result


# ── check_cve_exists ────────────────────────────────────────────────────────────

class TestCheckCveExists:
    def _mock_nvd(self, status_code=200, total_results=1):
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = {"totalResults": total_results}
        return resp

    def test_returns_true_when_cve_found(self):
        with patch("scripts.eval.requests.get", return_value=self._mock_nvd(200, 1)):
            assert check_cve_exists("CVE-2024-1234") is True

    def test_returns_false_when_cve_not_found(self):
        with patch("scripts.eval.requests.get", return_value=self._mock_nvd(200, 0)):
            assert check_cve_exists("CVE-9999-9999") is False

    def test_returns_false_on_non_200_response(self):
        with patch("scripts.eval.requests.get", return_value=self._mock_nvd(404, 0)):
            assert check_cve_exists("CVE-2024-1234") is False

    def test_returns_false_on_request_exception(self):
        import requests as req
        with patch("scripts.eval.requests.get", side_effect=req.exceptions.RequestException("timeout")):
            assert check_cve_exists("CVE-2024-1234") is False
