"""
backfill.py
-----------
ONE JOB: Reset error rows back to pending so the next pipeline run retries them.

Runs automatically every day at 01:30 UTC (stage=both).
Can also be triggered manually via GitHub Actions workflow_dispatch.

BACKFILL_STAGE env var:
  "both"       - resets all errors (default for cron)
  "parser"     - resets raw_articles where status='error' or status='processing'
  "extractors" - resets parsed_articles where any *_status='error'
"""

import os
from supabase import create_client

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]
STAGE = os.environ.get("BACKFILL_STAGE", "both")


def backfill_parser(db):
    for status in ("error", "processing"):
        result = (
            db.table("raw_articles")
            .update({"status": "pending", "error_message": None})
            .eq("status", status)
            .execute()
        )
        count = len(result.data) if result.data else 0
        print(f"Reset {count} raw_articles from '{status}' to 'pending'")


def backfill_extractors(db):
    for col in ("vuln_status", "method_status", "strategy_status"):
        result = (
            db.table("parsed_articles")
            .update({col: "pending"})
            .eq(col, "error")
            .execute()
        )
        count = len(result.data) if result.data else 0
        print(f"Reset {count} parsed_articles.{col} from 'error' to 'pending'")


def main():
    db = create_client(SUPABASE_URL, SUPABASE_KEY)
    print(f"Stage: {STAGE}")

    if STAGE in ("both", "parser"):
        backfill_parser(db)

    if STAGE in ("both", "extractors"):
        backfill_extractors(db)

    if STAGE not in ("both", "parser", "extractors"):
        print(f"Unknown BACKFILL_STAGE: {STAGE}")
        exit(1)

    print("Done.")


if __name__ == "__main__":
    main()
