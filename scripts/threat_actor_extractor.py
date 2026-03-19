"""
threat_actor_extractor.py
-------------------------
ONE JOB: Read claude_analysis.threat_actors from parsed_articles,
write one row per actor into the threat_actors table.
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
        .eq("actor_status", "pending")
        .limit(BATCH_SIZE)
        .execute()
        .data
    )

    print(f"Found {len(articles)} articles pending threat actor extraction")

    for article in articles:
        article_id = article["id"]
        actors = article["claude_analysis"].get("threat_actors", [])

        try:
            if actors:
                rows = []
                for a in actors:
                    rows.append({
                        "parsed_article_id": article_id,
                        "name": a.get("name", ""),
                        "aliases": a.get("aliases", []),
                        "origin_country": a.get("origin_country"),
                        "targeted_sectors": a.get("targeted_sectors", []),
                        "motivation": a.get("motivation"),
                    })
                db.table("threat_actors").insert(rows).execute()

            db.table("parsed_articles").update({"actor_status": "done"}).eq("id", article_id).execute()
            print(f"  {article_id[:8]}... - {len(actors)} threat actors inserted")

        except Exception as e:
            db.table("parsed_articles").update({
                "actor_status": "error"
            }).eq("id", article_id).execute()
            print(f"  {article_id[:8]}... ERROR: {e}")

    print("Done.")


if __name__ == "__main__":
    main()
