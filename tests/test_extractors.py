"""
test_extractors.py
------------------
Tests for all 5 extractors — field mapping, needs_review logic, review_queue insertion.
"""

import pytest
from unittest.mock import patch, MagicMock
from tests.conftest import make_mock_db, FakeTable


# ── Shared article builder ───────────────────────────────────────────────────────

def make_article(article_id="article-uuid-1234", ai_analysis=None):
    return {"id": article_id, "ai_analysis": ai_analysis or {}}


# ── vuln_extractor ──────────────────────────────────────────────────────────────

class TestVulnExtractor:
    def _run(self, articles):
        db, tables = make_mock_db({"parsed_articles": articles})
        tables["vulnerabilities"] = FakeTable()
        with patch("scripts.vuln_extractor.create_client", return_value=db):
            from scripts.vuln_extractor import main
            main()
        return tables

    def test_maps_all_fields_correctly(self):
        vuln = {
            "cve_id": "CVE-2024-1234",
            "description": "Remote code execution",
            "affected_products": ["Windows 10", "Windows 11"],
            "severity": "critical",
            "cvss_score": 9.8,
            "patch_available": True,
            "patch_url": "https://example.com/patch",
        }
        tables = self._run([make_article(ai_analysis={"vulnerabilities": [vuln]})])
        inserted = tables["vulnerabilities"].inserted
        assert len(inserted) == 1
        row = inserted[0]
        assert row["cve_id"] == "CVE-2024-1234"
        assert row["vuln_description"] == "Remote code execution"
        assert row["severity"] == "critical"
        assert row["cvss_score"] == 9.8
        assert row["patch_available"] is True

    def test_skips_insert_when_no_vulnerabilities(self):
        tables = self._run([make_article(ai_analysis={"vulnerabilities": []})])
        assert tables["vulnerabilities"].inserted == []

    def test_handles_null_cve_id(self):
        vuln = {"cve_id": None, "description": "Unknown vuln", "affected_products": [], "severity": "high", "cvss_score": None, "patch_available": False, "patch_url": None}
        tables = self._run([make_article(ai_analysis={"vulnerabilities": [vuln]})])
        assert tables["vulnerabilities"].inserted[0]["cve_id"] is None

    def test_multiple_vulns_inserts_all(self):
        vulns = [
            {"cve_id": f"CVE-2024-000{i}", "description": f"Vuln {i}", "affected_products": [], "severity": "high", "cvss_score": 7.0, "patch_available": True, "patch_url": None}
            for i in range(3)
        ]
        tables = self._run([make_article(ai_analysis={"vulnerabilities": vulns})])
        assert len(tables["vulnerabilities"].inserted) == 3


# ── methodology_extractor ───────────────────────────────────────────────────────

class TestMethodologyExtractor:
    def _run(self, articles):
        db, tables = make_mock_db({"parsed_articles": articles})
        tables["methodologies"] = FakeTable()
        tables["review_queue"] = FakeTable()
        with patch("scripts.methodology_extractor.create_client", return_value=db):
            from scripts.methodology_extractor import main
            main()
        return tables

    def _make_technique(self, needs_review=False, mitre_id="T1566.001", suggestion=None):
        return {
            "name": "Spear Phishing",
            "mitre_id": mitre_id,
            "mitre_tactic": "Initial Access",
            "description": "Used phishing emails",
            "threat_actor": "Lazarus",
            "needs_review": needs_review,
            "mitre_suggested": suggestion,
        }

    def test_valid_technique_inserted_to_methodologies(self):
        t = self._make_technique(needs_review=False)
        tables = self._run([make_article(ai_analysis={"techniques": [t], "rag_candidates": []})])
        assert len(tables["methodologies"].inserted) == 1
        assert tables["methodologies"].inserted[0]["technique_name"] == "Spear Phishing"
        assert tables["methodologies"].inserted[0]["mitre_technique_id"] == "T1566.001"

    def test_needs_review_true_inserts_into_review_queue(self):
        t = self._make_technique(needs_review=True, mitre_id=None, suggestion="T9999.999")
        tables = self._run([make_article(ai_analysis={"techniques": [t], "rag_candidates": ["T1566.001"]})])
        assert len(tables["review_queue"].inserted) == 1

    def test_needs_review_stores_gemma_suggestion(self):
        t = self._make_technique(needs_review=True, mitre_id=None, suggestion="T9999.999")
        tables = self._run([make_article(ai_analysis={"techniques": [t], "rag_candidates": []})])
        assert tables["review_queue"].inserted[0]["gemma_suggestion"] == "T9999.999"

    def test_needs_review_stores_rag_candidates(self):
        t = self._make_technique(needs_review=True, mitre_id=None)
        rag = ["T1566.001", "T1059.001"]
        tables = self._run([make_article(ai_analysis={"techniques": [t], "rag_candidates": rag})])
        assert tables["review_queue"].inserted[0]["rag_candidates"] == rag

    def test_no_review_queue_when_needs_review_false(self):
        t = self._make_technique(needs_review=False)
        tables = self._run([make_article(ai_analysis={"techniques": [t], "rag_candidates": []})])
        assert tables["review_queue"].inserted == []

    def test_mixed_techniques_splits_correctly(self):
        t_valid = self._make_technique(needs_review=False)
        t_review = self._make_technique(needs_review=True, mitre_id=None)
        tables = self._run([make_article(ai_analysis={"techniques": [t_valid, t_review], "rag_candidates": []})])
        assert len(tables["methodologies"].inserted) == 2
        assert len(tables["review_queue"].inserted) == 1

    def test_review_queue_behavior_text_from_description(self):
        t = self._make_technique(needs_review=True, mitre_id=None)
        tables = self._run([make_article(ai_analysis={"techniques": [t], "rag_candidates": []})])
        assert tables["review_queue"].inserted[0]["behavior_text"] == "Used phishing emails"

    def test_review_type_is_mitre_no_match(self):
        t = self._make_technique(needs_review=True, mitre_id=None)
        tables = self._run([make_article(ai_analysis={"techniques": [t], "rag_candidates": []})])
        assert tables["review_queue"].inserted[0]["review_type"] == "mitre_no_match"

    def test_empty_techniques_no_insert(self):
        tables = self._run([make_article(ai_analysis={"techniques": [], "rag_candidates": []})])
        assert tables["methodologies"].inserted == []
        assert tables["review_queue"].inserted == []


# ── backfill integration check (strategy / actor / incident) ────────────────────

class TestOtherExtractors:
    """Smoke tests — verify field mapping for remaining extractors."""

    def _run_extractor(self, module_name, table_name, ai_key, articles):
        db, tables = make_mock_db({"parsed_articles": articles})
        tables[table_name] = FakeTable()
        with patch(f"scripts.{module_name}.create_client", return_value=db):
            import importlib
            mod = importlib.import_module(f"scripts.{module_name}")
            mod.main()
        return tables

    def test_strategy_extractor_maps_recommendation(self):
        rec = {
            "text": "Enable MFA",
            "category": "config",
            "priority": "immediate",
            "applies_to": ["sysadmin"],
            "related_cves": [],
        }
        article = make_article(ai_analysis={"recommendations": [rec]})
        tables = self._run_extractor("strategy_extractor", "strategies", "recommendations", [article])
        assert tables["strategies"].inserted[0]["recommendation"] == "Enable MFA"
        assert tables["strategies"].inserted[0]["category"] == "config"

    def test_threat_actor_extractor_maps_aliases(self):
        actor = {
            "name": "Lazarus Group",
            "aliases": ["Hidden Cobra", "ZINC"],
            "origin_country": "North Korea",
            "targeted_sectors": ["government"],
            "motivation": "espionage",
        }
        article = make_article(ai_analysis={"threat_actors": [actor]})
        tables = self._run_extractor("threat_actor_extractor", "threat_actors", "threat_actors", [article])
        row = tables["threat_actors"].inserted[0]
        assert row["name"] == "Lazarus Group"
        assert row["aliases"] == ["Hidden Cobra", "ZINC"]
        assert row["motivation"] == "espionage"

    def test_incident_extractor_maps_all_fields(self):
        incident = {
            "organization": "Acme Corp",
            "sector": "finance",
            "attack_type": "ransomware",
            "data_compromised": ["PII", "credentials"],
            "incident_date": "2024-01-15",
        }
        article = make_article(ai_analysis={"incidents": [incident]})
        tables = self._run_extractor("incident_extractor", "incidents", "incidents", [article])
        row = tables["incidents"].inserted[0]
        assert row["organization"] == "Acme Corp"
        assert row["attack_type"] == "ransomware"
        assert row["incident_date"] == "2024-01-15"
