"""
conftest.py
-----------
Shared fixtures and env var setup for all tests.
Must set env vars BEFORE any script module is imported.
"""

import os
import sys

from dotenv import load_dotenv

load_dotenv()
# ── Set env vars before importing any scripts (they read os.environ at module level) ──
os.environ.setdefault("SUPABASE_URL", "https://test.supabase.co")
os.environ.setdefault("SUPABASE_KEY", "test-service-key")
os.environ.setdefault("SUPABASE_SERVICE_KEY", "test-service-key")
os.environ.setdefault("GEMINI_API_KEY", "test-gemini-key")
os.environ.setdefault("NVD_API_KEY", "test-nvd-key")

# Add project root to path so scripts can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from unittest.mock import MagicMock


# ── Shared DB mock factory ──────────────────────────────────────────────────────

class FakeTable:
    """Chainable fake supabase table that records inserts and updates."""

    def __init__(self, data=None):
        self._data = data or []
        self.inserted = []
        self.updated = []
        self._filter = {}

    # ── query chain ──
    def select(self, *a, **kw): return self
    def eq(self, *a, **kw): return self
    def not_(self): return self
    def is_(self, *a, **kw): return self
    def order(self, *a, **kw): return self
    def limit(self, *a, **kw): return self
    def gte(self, *a, **kw): return self

    def insert(self, rows):
        if isinstance(rows, list):
            self.inserted.extend(rows)
        else:
            self.inserted.append(rows)
        return self

    def upsert(self, rows, **kw):
        if isinstance(rows, list):
            self.inserted.extend(rows)
        else:
            self.inserted.append(rows)
        return self

    def update(self, data):
        self.updated.append(data)
        return self

    def execute(self):
        result = MagicMock()
        result.data = self._data
        result.count = len(self._data)
        return result

    # support .not_.is_() chaining
    def __getattr__(self, name):
        return self


def make_mock_db(tables: dict = None):
    """
    Returns a mock supabase client.
    tables: dict of table_name → list of rows (returned by .execute().data)
    """
    tables = tables or {}
    fake_tables = {name: FakeTable(rows) for name, rows in tables.items()}
    default_table = FakeTable()

    db = MagicMock()
    db.table.side_effect = lambda name: fake_tables.setdefault(name, FakeTable())
    db.rpc.return_value = FakeTable()
    return db, fake_tables


@pytest.fixture
def mock_db():
    """Basic empty mock DB."""
    db, _ = make_mock_db()
    return db
