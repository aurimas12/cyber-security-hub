"""
test_article_parser.py
----------------------
Tests for clean_json, format_rag_candidates, call_gemma_with_retry retry logic.
"""

import json
import pytest
from unittest.mock import MagicMock, patch

from scripts.article_parser import (
    clean_json,
    format_rag_candidates,
    call_gemma_with_retry,
    MAX_RETRIES,
)
from google.genai import errors as genai_errors


# ── Helpers ─────────────────────────────────────────────────────────────────────

VALID_JSON = json.dumps({
    "summary": "test summary",
    "vulnerabilities": [],
    "techniques": [],
    "recommendations": [],
    "threat_actors": [],
    "incidents": [],
})


def make_response(text: str):
    r = MagicMock()
    r.text = text
    return r


def make_client(side_effects):
    """side_effects: list of responses or exceptions for generate_content."""
    client = MagicMock()
    client.models.generate_content.side_effect = side_effects
    return client


# ── clean_json ──────────────────────────────────────────────────────────────────

class TestCleanJson:
    def test_strips_json_markdown_fence(self):
        raw = "```json\n{\"key\": \"value\"}\n```"
        assert clean_json(raw) == '{"key": "value"}'

    def test_strips_plain_markdown_fence(self):
        raw = "```\n{\"key\": \"value\"}\n```"
        assert clean_json(raw) == '{"key": "value"}'

    def test_no_fences_unchanged(self):
        raw = '{"key": "value"}'
        assert clean_json(raw) == raw

    def test_strips_surrounding_whitespace(self):
        raw = '  {"key": "value"}  '
        assert clean_json(raw) == '{"key": "value"}'

    def test_strips_fence_with_no_newline(self):
        raw = "```json{\"key\": \"value\"}```"
        result = clean_json(raw)
        assert '{"key": "value"}' in result


# ── format_rag_candidates ───────────────────────────────────────────────────────

class TestFormatRagCandidates:
    def test_empty_returns_fallback_message(self):
        result = format_rag_candidates([])
        assert "empty" in result.lower() or "no candidates" in result.lower()

    def test_includes_technique_id(self):
        candidates = [{"technique_id": "T1566.001", "name": "Spear Phishing", "tactic": "Initial Access"}]
        result = format_rag_candidates(candidates)
        assert "T1566.001" in result

    def test_includes_name_and_tactic(self):
        candidates = [{"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}]
        result = format_rag_candidates(candidates)
        assert "PowerShell" in result
        assert "Execution" in result

    def test_multiple_candidates_each_on_own_line(self):
        candidates = [
            {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
            {"technique_id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
        ]
        result = format_rag_candidates(candidates)
        lines = [l for l in result.split("\n") if l.strip()]
        assert len(lines) == 2

    def test_five_candidates_five_lines(self):
        candidates = [
            {"technique_id": f"T100{i}", "name": f"Tech {i}", "tactic": "Execution"}
            for i in range(5)
        ]
        result = format_rag_candidates(candidates)
        lines = [l for l in result.split("\n") if l.strip()]
        assert len(lines) == 5


# ── call_gemma_with_retry ───────────────────────────────────────────────────────

class TestCallGemmaWithRetry:

    def test_returns_parsed_dict_on_success(self):
        client = make_client([make_response(VALID_JSON)])
        result = call_gemma_with_retry(client, "title", "content", "candidates")
        assert result["summary"] == "test summary"
        assert result["vulnerabilities"] == []

    def test_called_with_correct_model(self):
        client = make_client([make_response(VALID_JSON)])
        call_gemma_with_retry(client, "title", "content", "")
        args, kwargs = client.models.generate_content.call_args
        assert kwargs.get("model") == "gemma-3-12b-it" or args[0] == "gemma-3-12b-it" or "gemma" in str(client.models.generate_content.call_args)

    def test_retries_on_json_decode_error_then_succeeds(self):
        bad = make_response("NOT VALID JSON <<<")
        good = make_response(VALID_JSON)
        client = make_client([bad, good])

        with patch("scripts.article_parser.time.sleep"):
            result = call_gemma_with_retry(client, "title", "content", "")

        assert result["summary"] == "test summary"
        assert client.models.generate_content.call_count == 2

    def test_raises_json_decode_error_after_max_retries(self):
        bad = make_response("NOT VALID JSON <<<")
        client = make_client([bad] * MAX_RETRIES)

        with patch("scripts.article_parser.time.sleep"):
            with pytest.raises(json.JSONDecodeError):
                call_gemma_with_retry(client, "title", "content", "")

        assert client.models.generate_content.call_count == MAX_RETRIES

    def test_retries_on_server_error_then_succeeds(self):
        server_err = genai_errors.ServerError(503, {}, MagicMock())
        good = make_response(VALID_JSON)
        client = make_client([server_err, good])

        with patch("scripts.article_parser.time.sleep"):
            result = call_gemma_with_retry(client, "title", "content", "")

        assert result["summary"] == "test summary"
        assert client.models.generate_content.call_count == 2

    def test_raises_server_error_after_max_retries(self):
        server_err = genai_errors.ServerError(503, {}, MagicMock())
        client = make_client([server_err] * MAX_RETRIES)

        with patch("scripts.article_parser.time.sleep"):
            with pytest.raises(genai_errors.ServerError):
                call_gemma_with_retry(client, "title", "content", "")

    def test_content_truncated_to_limit(self):
        long_content = "x" * 10_000
        client = make_client([make_response(VALID_JSON)])
        call_gemma_with_retry(client, "title", long_content, "")
        call_args = client.models.generate_content.call_args
        prompt = call_args.kwargs.get("contents") or call_args.args[1]
        # Content must be capped — 10000 chars should not appear verbatim
        assert "x" * 7000 not in prompt

    def test_rag_candidates_included_in_prompt(self):
        client = make_client([make_response(VALID_JSON)])
        call_gemma_with_retry(client, "title", "content", "• T1566.001 | Phishing | Initial Access")
        call_args = client.models.generate_content.call_args
        prompt = call_args.kwargs.get("contents") or call_args.args[1]
        assert "T1566.001" in prompt
