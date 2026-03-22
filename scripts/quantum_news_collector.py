"""
quantum_news_collector.py
--------------------------
ONE JOB: Pull quantum computing RSS feeds, insert new articles into quantum_raw_articles.
Runs every 6 hours via GitHub Actions.

Idempotent - url UNIQUE constraint means duplicates are silently skipped.
"""

import os
from dotenv import load_dotenv
import feedparser
from datetime import datetime, timezone
from supabase import create_client

load_dotenv()

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]

QUANTUM_FEEDS = [
    # ── Quantum computing news portals ──────────────────────────────────────────
    {"name": "quanta_magazine", "url": "https://www.quantamagazine.org/feed/"},

    # ── Science & research ───────────────────────────────────────────────────────
    {"name": "sciencedaily_qc", "url": "https://www.sciencedaily.com/rss/computers_math/quantum_computers.xml"},
    {"name": "nature_qi",       "url": "https://www.nature.com/npjqi.rss"},

    # ── Industry & standards ─────────────────────────────────────────────────────
    {"name": "ieee_quantum",    "url": "https://quantum.ieee.org/feed/"},
    {"name": "nist_news",       "url": "https://www.nist.gov/news-events/news/rss.xml"},
]


def parse_date(entry) -> str | None:
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        dt = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
        return dt.isoformat()
    return None


def get_content(entry) -> str:
    if hasattr(entry, "content") and entry.content:
        return entry.content[0].value
    if hasattr(entry, "summary"):
        return entry.summary
    return ""


def get_tags(entry) -> list[str]:
    if hasattr(entry, "tags") and entry.tags:
        return [t["term"] for t in entry.tags if t.get("term")]
    return []


def main():
    client = create_client(SUPABASE_URL, SUPABASE_KEY)
    total_inserted = 0

    for feed in QUANTUM_FEEDS:
        print(f"[{feed['name']}] Fetching {feed['url']}")
        parsed = feedparser.parse(feed["url"])

        if parsed.bozo:
            print(f"[{feed['name']}] WARNING: feed parse error - {parsed.bozo_exception}")

        rows = []
        for entry in parsed.entries:
            url = getattr(entry, "link", None)
            title = getattr(entry, "title", None)
            if not url or not title:
                continue

            rows.append({
                "source_feed": feed["name"],
                "title": title,
                "url": url,
                "author": getattr(entry, "author", None),
                "published_at": parse_date(entry),
                "tags": get_tags(entry),
                "raw_content": get_content(entry),
            })

        if not rows:
            print(f"[{feed['name']}] No entries found")
            continue

        result = (
            client.table("quantum_raw_articles")
            .upsert(rows, on_conflict="url", ignore_duplicates=True)
            .execute()
        )
        inserted = len(result.data) if result.data else 0
        total_inserted += inserted
        print(f"[{feed['name']}] {len(rows)} entries fetched, {inserted} new inserted")

    print(f"\nDone. Total new quantum articles: {total_inserted}")


if __name__ == "__main__":
    main()
