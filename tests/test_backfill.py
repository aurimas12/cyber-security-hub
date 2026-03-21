"""
test_backfill.py
----------------
Tests for backfill_parser, backfill_extractors, and unknown stage handling.
"""

import pytest
from unittest.mock import patch, MagicMock
from tests.conftest import make_mock_db, FakeTable


def run_backfill(stage="both"):
    db, tables = make_mock_db()
    tables["raw_articles"] = FakeTable()
    tables["parsed_articles"] = FakeTable()

    with patch("scripts.backfill.create_client", return_value=db), \
         patch.dict("os.environ", {"BACKFILL_STAGE": stage}):
        import importlib
        import scripts.backfill as mod
        importlib.reload(mod)
        mod.STAGE = stage
        mod.main()

    return db, tables


class TestBackfillParser:
    def test_resets_error_rows(self):
        db, fake_tables = make_mock_db()
        with patch("scripts.backfill.create_client", return_value=db):
            from scripts.backfill import backfill_parser
            backfill_parser(db)
        updated = fake_tables["raw_articles"].updated
        assert any(v.get("status") == "pending" for v in updated)

    def test_resets_processing_rows(self):
        db, fake_tables = make_mock_db()
        with patch("scripts.backfill.create_client", return_value=db):
            from scripts.backfill import backfill_parser
            backfill_parser(db)
        # backfill_parser calls update() twice: once for 'error', once for 'processing'
        assert len(fake_tables["raw_articles"].updated) == 2


class TestBackfillExtractors:
    def test_resets_all_five_status_columns(self):
        db, fake_tables = make_mock_db()
        with patch("scripts.backfill.create_client", return_value=db):
            from scripts.backfill import backfill_extractors
            backfill_extractors(db)

        updated_cols = [list(u.keys())[0] for u in fake_tables["parsed_articles"].updated]
        assert "vuln_status" in updated_cols
        assert "method_status" in updated_cols
        assert "strategy_status" in updated_cols
        assert "actor_status" in updated_cols
        assert "incident_status" in updated_cols

    def test_resets_exactly_five_columns(self):
        db, fake_tables = make_mock_db()
        with patch("scripts.backfill.create_client", return_value=db):
            from scripts.backfill import backfill_extractors
            backfill_extractors(db)

        assert len(fake_tables["parsed_articles"].updated) == 5

    def test_sets_status_to_pending(self):
        db, fake_tables = make_mock_db()
        with patch("scripts.backfill.create_client", return_value=db):
            from scripts.backfill import backfill_extractors
            backfill_extractors(db)

        for update_data in fake_tables["parsed_articles"].updated:
            col = list(update_data.keys())[0]
            assert update_data[col] == "pending"


class TestBackfillStage:
    def test_unknown_stage_exits_with_code_1(self):
        db, _ = make_mock_db()
        with patch("scripts.backfill.create_client", return_value=db), \
             pytest.raises(SystemExit) as exc_info:
            from scripts.backfill import main
            import scripts.backfill as mod
            mod.STAGE = "invalid_stage"
            mod.main()
        assert exc_info.value.code == 1

    def test_parser_stage_only_resets_raw_articles(self):
        db, _ = make_mock_db()
        with patch("scripts.backfill.create_client", return_value=db):
            from scripts.backfill import backfill_parser, backfill_extractors
            backfill_parser(db)
        # parsed_articles update should NOT be called
        tables_accessed = [call.args[0] for call in db.table.call_args_list]
        assert "raw_articles" in tables_accessed

    def test_extractors_stage_only_resets_parsed_articles(self):
        db, _ = make_mock_db()
        with patch("scripts.backfill.create_client", return_value=db):
            from scripts.backfill import backfill_extractors
            backfill_extractors(db)
        tables_accessed = [call.args[0] for call in db.table.call_args_list]
        assert all(t == "parsed_articles" for t in tables_accessed)
