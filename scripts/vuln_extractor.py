"""
vuln_extractor.py
-----------------
ONE JOB: Read claude_analysis.vulnerabilities from parsed_articles,
write one row per vulnerability into the vulnerabilities table.
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
        .eq("vuln_status", "pending")
        .limit(BATCH_SIZE)
        .execute()
        .data
    )

    print(f"Found {len(articles)} articles pending vuln extraction")

    for article in articles:
        article_id = article["id"]
        vulns = article["claude_analysis"].get("vulnerabilities", [])

        try:
            if vulns:
                rows = []
                for v in vulns:
                    rows.append({
                        "parsed_article_id": article_id,
                        "cve_id": v.get("cve_id"),
                        "vuln_description": v.get("description", ""),
                        "affected_products": v.get("affected_products", []),
                        "severity": v.get("severity"),
                        "cvss_score": v.get("cvss_score"),
                        "patch_available": v.get("patch_available"),
                        "patch_url": v.get("patch_url"),
                    })
                db.table("vulnerabilities").insert(rows).execute()

            db.table("parsed_articles").update({"vuln_status": "done"}).eq("id", article_id).execute()
            print(f"  {article_id[:8]}... - {len(vulns)} vulnerabilities inserted")

        except Exception as e:
            db.table("parsed_articles").update({
                "vuln_status": "error"
            }).eq("id", article_id).execute()
            print(f"  {article_id[:8]}... ERROR: {e}")

    print("Done.")


if __name__ == "__main__":
    main()
