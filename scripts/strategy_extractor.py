"""
strategy_extractor.py
---------------------
ONE JOB: Read claude_analysis.recommendations from parsed_articles,
write one row per recommendation into the strategies table.
No API calls - pure data transformation.
"""

import os
from supabase import create_client

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]

BATCH_SIZE = 50


def main():
    db = create_client(SUPABASE_URL, SUPABASE_KEY)

    articles = (
        db.table("parsed_articles")
        .select("id, claude_analysis")
        .eq("strategy_status", "pending")
        .limit(BATCH_SIZE)
        .execute()
        .data
    )

    print(f"Found {len(articles)} articles pending strategy extraction")

    for article in articles:
        article_id = article["id"]
        recommendations = article["claude_analysis"].get("recommendations", [])

        try:
            if recommendations:
                rows = []
                for r in recommendations:
                    rows.append({
                        "parsed_article_id": article_id,
                        "recommendation": r.get("text", ""),
                        "category": r.get("category"),
                        "priority": r.get("priority"),
                        "applies_to": r.get("applies_to", []),
                        "related_cve_ids": r.get("related_cves", []),
                    })
                db.table("strategies").insert(rows).execute()

            db.table("parsed_articles").update({"strategy_status": "done"}).eq("id", article_id).execute()
            print(f"  {article_id[:8]}... - {len(recommendations)} strategies inserted")

        except Exception as e:
            db.table("parsed_articles").update({
                "strategy_status": "error"
            }).eq("id", article_id).execute()
            print(f"  {article_id[:8]}... ERROR: {e}")

    print("Done.")


if __name__ == "__main__":
    main()
