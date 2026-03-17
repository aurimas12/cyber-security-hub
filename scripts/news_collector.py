"""
news_collector.py
-----------------
ONE JOB: Pull RSS feeds, insert new articles into raw_articles.
Runs every 6 hours via GitHub Actions.

Idempotent - url UNIQUE constraint means duplicates are silently skipped.
"""

import os
import feedparser
from datetime import datetime, timezone
from supabase import create_client

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]

RSS_FEEDS = [
    {"name": "krebs",            "url": "https://krebsonsecurity.com/feed/"},
    {"name": "bleepingcomputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "hackernews",       "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "cisa_alerts",      "url": "https://www.cisa.gov/cybersecurity-advisories/advisories.xml"},
    {"name": "schneier",         "url": "https://www.schneier.com/feed/atom/"},
    {"name": "darkreading",      "url": "https://www.darkreading.com/rss.xml"},
    {"name": "sans_isc",         "url": "https://isc.sans.edu/rssfeed_full.xml"},
    {"name": "nvd_cve",          "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"},
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


def main():
    client = create_client(SUPABASE_URL, SUPABASE_KEY)
    total_inserted = 0

    for feed in RSS_FEEDS:
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
                "published_at": parse_date(entry),
                "raw_content": get_content(entry),
                "status": "pending",
            })

        if not rows:
            print(f"[{feed['name']}] No entries found")
            continue

        # ON CONFLICT DO NOTHING via upsert with ignoreDuplicates
        result = (
            client.table("raw_articles")
            .upsert(rows, on_conflict="url", ignore_duplicates=True)
            .execute()
        )
        inserted = len(result.data) if result.data else 0
        total_inserted += inserted
        print(f"[{feed['name']}] {len(rows)} entries fetched, {inserted} new inserted")

    print(f"\nDone. Total new articles: {total_inserted}")


if __name__ == "__main__":
    main()
