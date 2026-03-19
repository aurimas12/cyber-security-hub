"""
incident_extractor.py
---------------------
ONE JOB: Read claude_analysis.incidents from parsed_articles,
write one row per incident into the incidents table.
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
        .eq("incident_status", "pending")
        .limit(BATCH_SIZE)
        .execute()
        .data
    )

    print(f"Found {len(articles)} articles pending incident extraction")

    for article in articles:
        article_id = article["id"]
        incidents = article["claude_analysis"].get("incidents", [])

        try:
            if incidents:
                rows = []
                for inc in incidents:
                    rows.append({
                        "parsed_article_id": article_id,
                        "organization": inc.get("organization"),
                        "sector": inc.get("sector"),
                        "attack_type": inc.get("attack_type"),
                        "data_compromised": inc.get("data_compromised", []),
                        "incident_date": inc.get("incident_date"),
                    })
                db.table("incidents").insert(rows).execute()

            db.table("parsed_articles").update({"incident_status": "done"}).eq("id", article_id).execute()
            print(f"  {article_id[:8]}... - {len(incidents)} incidents inserted")

        except Exception as e:
            db.table("parsed_articles").update({
                "incident_status": "error"
            }).eq("id", article_id).execute()
            print(f"  {article_id[:8]}... ERROR: {e}")

    print("Done.")


if __name__ == "__main__":
    main()
