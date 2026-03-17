"""
methodology_extractor.py
------------------------
ONE JOB: Read claude_analysis.techniques from parsed_articles,
write one row per technique into the methodologies table.
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
        .eq("method_status", "pending")
        .limit(BATCH_SIZE)
        .execute()
        .data
    )

    print(f"Found {len(articles)} articles pending methodology extraction")

    for article in articles:
        article_id = article["id"]
        techniques = article["claude_analysis"].get("techniques", [])

        try:
            if techniques:
                rows = []
                for t in techniques:
                    rows.append({
                        "parsed_article_id": article_id,
                        "technique_name": t.get("name", ""),
                        "mitre_technique_id": t.get("mitre_id"),
                        "mitre_tactic": t.get("mitre_tactic"),
                        "description": t.get("description", ""),
                        "threat_actor": t.get("threat_actor"),
                    })
                db.table("methodologies").insert(rows).execute()

            db.table("parsed_articles").update({"method_status": "done"}).eq("id", article_id).execute()
            print(f"  {article_id[:8]}... - {len(techniques)} techniques inserted")

        except Exception as e:
            db.table("parsed_articles").update({
                "method_status": "error"
            }).eq("id", article_id).execute()
            print(f"  {article_id[:8]}... ERROR: {e}")

    print("Done.")


if __name__ == "__main__":
    main()
