"""
backfill.py
-----------
ONE JOB: Reset error rows back to pending so the next pipeline run retries them.
Triggered manually via GitHub Actions workflow_dispatch.

BACKFILL_STAGE env var:
  "parser"     - resets raw_articles where status='error' or status='processing'
  "extractors" - resets parsed_articles where any *_status='error'
"""

import os
from supabase import create_client

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]
STAGE = os.environ.get("BACKFILL_STAGE", "parser")


def main():
    db = create_client(SUPABASE_URL, SUPABASE_KEY)

    if STAGE == "parser":
        for status in ("error", "processing"):
            result = (
                db.table("raw_articles")
                .update({"status": "pending", "error_message": None})
                .eq("status", status)
                .execute()
            )
            count = len(result.data) if result.data else 0
            print(f"Reset {count} raw_articles from '{status}' to 'pending'")

    elif STAGE == "extractors":
        for col in ("vuln_status", "method_status", "strategy_status"):
            result = (
                db.table("parsed_articles")
                .update({col: "pending"})
                .eq(col, "error")
                .execute()
            )
            count = len(result.data) if result.data else 0
            print(f"Reset {count} parsed_articles.{col} from 'error' to 'pending'")

    else:
        print(f"Unknown BACKFILL_STAGE: {STAGE}. Use 'parser' or 'extractors'.")
        exit(1)

    print("Done.")


if __name__ == "__main__":
    main()
