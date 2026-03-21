"""
test_setup_mitre_embeddings.py
-------------------------------
Tests for fetch_mitre_techniques STIX parsing logic.
"""

import pytest
from unittest.mock import patch, MagicMock

from scripts.setup_mitre_embeddings import fetch_mitre_techniques


def _make_stix_bundle(objects):
    return {"objects": objects}


def _make_attack_pattern(technique_id, name="Test Technique", deprecated=False, revoked=False, tactic="execution"):
    return {
        "type": "attack-pattern",
        "name": name,
        "description": f"Description of {technique_id}",
        "x_mitre_deprecated": deprecated,
        "revoked": revoked,
        "external_references": [
            {"source_name": "mitre-attack", "external_id": technique_id}
        ],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tactic}],
    }


def _mock_response(bundle):
    resp = MagicMock()
    resp.json.return_value = bundle
    resp.raise_for_status = MagicMock()
    return resp


class TestFetchMitreTechniques:
    def test_returns_list_of_dicts(self):
        bundle = _make_stix_bundle([_make_attack_pattern("T1566")])
        with patch("scripts.setup_mitre_embeddings.requests.get", return_value=_mock_response(bundle)):
            result = fetch_mitre_techniques()
        assert isinstance(result, list)
        assert all(isinstance(t, dict) for t in result)

    def test_technique_id_starts_with_T(self):
        bundle = _make_stix_bundle([_make_attack_pattern("T1566")])
        with patch("scripts.setup_mitre_embeddings.requests.get", return_value=_mock_response(bundle)):
            result = fetch_mitre_techniques()
        assert all(t["technique_id"].startswith("T") for t in result)

    def test_filters_out_deprecated(self):
        bundle = _make_stix_bundle([_make_attack_pattern("T1086", deprecated=True)])
        with patch("scripts.setup_mitre_embeddings.requests.get", return_value=_mock_response(bundle)):
            result = fetch_mitre_techniques()
        ids = [t["technique_id"] for t in result]
        assert "T1086" not in ids

    def test_filters_out_revoked(self):
        bundle = _make_stix_bundle([_make_attack_pattern("T1500", revoked=True)])
        with patch("scripts.setup_mitre_embeddings.requests.get", return_value=_mock_response(bundle)):
            result = fetch_mitre_techniques()
        ids = [t["technique_id"] for t in result]
        assert "T1500" not in ids

    def test_filters_out_non_attack_pattern_objects(self):
        malware = {"type": "malware", "name": "Bad.exe", "external_references": [
            {"source_name": "mitre-attack", "external_id": "T9000"}
        ]}
        bundle = _make_stix_bundle([malware, _make_attack_pattern("T1566")])
        with patch("scripts.setup_mitre_embeddings.requests.get", return_value=_mock_response(bundle)):
            result = fetch_mitre_techniques()
        ids = [t["technique_id"] for t in result]
        assert "T9000" not in ids
        assert "T1566" in ids

    def test_embed_text_contains_name_tactic_description(self):
        bundle = _make_stix_bundle([_make_attack_pattern("T1566", name="Phishing", tactic="initial-access")])
        with patch("scripts.setup_mitre_embeddings.requests.get", return_value=_mock_response(bundle)):
            result = fetch_mitre_techniques()
        embed_text = result[0]["embed_text"]
        assert "Phishing" in embed_text
        assert "Initial Access" in embed_text  # tactic is title-cased
        assert "Description of T1566" in embed_text

    def test_tactic_hyphen_converted_to_space_titlecase(self):
        bundle = _make_stix_bundle([_make_attack_pattern("T1059", tactic="defense-evasion")])
        with patch("scripts.setup_mitre_embeddings.requests.get", return_value=_mock_response(bundle)):
            result = fetch_mitre_techniques()
        assert result[0]["tactic"] == "Defense Evasion"

    def test_description_truncated_to_600_chars(self):
        long_obj = _make_attack_pattern("T1566")
        long_obj["description"] = "x" * 1000
        bundle = _make_stix_bundle([long_obj])
        with patch("scripts.setup_mitre_embeddings.requests.get", return_value=_mock_response(bundle)):
            result = fetch_mitre_techniques()
        assert len(result[0]["description"]) <= 600

    def test_all_required_keys_present(self):
        bundle = _make_stix_bundle([_make_attack_pattern("T1566")])
        with patch("scripts.setup_mitre_embeddings.requests.get", return_value=_mock_response(bundle)):
            result = fetch_mitre_techniques()
        required_keys = {"technique_id", "name", "tactic", "description", "embed_text"}
        assert required_keys.issubset(result[0].keys())

    def test_empty_bundle_returns_empty_list(self):
        bundle = _make_stix_bundle([])
        with patch("scripts.setup_mitre_embeddings.requests.get", return_value=_mock_response(bundle)):
            result = fetch_mitre_techniques()
        assert result == []
