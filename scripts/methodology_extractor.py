"""
methodology_extractor.py
------------------------
ONE JOB: Read ai_analysis.techniques from parsed_articles,
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
        .select("id, ai_analysis")
        .eq("method_status", "pending")
        .order("parsed_at")
        .limit(BATCH_SIZE)
        .execute()
        .data
    )

    print(f"Found {len(articles)} articles pending methodology extraction")

    for article in articles:
        article_id = article["id"]
        techniques = article["ai_analysis"].get("techniques", [])

        try:
            method_rows = []
            review_rows = []

            for t in techniques:
                method_rows.append({
                    "parsed_article_id": article_id,
                    "technique_name": t.get("name", ""),
                    "mitre_technique_id": t.get("mitre_id"),
                    "mitre_tactic": t.get("mitre_tactic"),
                    "description": t.get("description", ""),
                    "threat_actor": t.get("threat_actor"),
                })

                if t.get("needs_review"):
                    review_rows.append({
                        "parsed_article_id": article_id,
                        "review_type": "mitre_no_match",
                        "behavior_text": t.get("description", ""),
                        "gemma_suggestion": t.get("mitre_suggested"),
                        "rag_candidates": article["ai_analysis"].get("rag_candidates", []),
                    })

            if method_rows:
                db.table("methodologies").insert(method_rows).execute()
            if review_rows:
                db.table("review_queue").insert(review_rows).execute()

            db.table("parsed_articles").update({"method_status": "done"}).eq("id", article_id).execute()
            flagged = len(review_rows)
            print(f"  {article_id[:8]}... - {len(method_rows)} techniques"
                  + (f", {flagged} flagged for review" if flagged else ""))

        except Exception as e:
            db.table("parsed_articles").update({
                "method_status": "error"
            }).eq("id", article_id).execute()
            print(f"  {article_id[:8]}... ERROR: {e}")

    print("Done.")


if __name__ == "__main__":
    main()
