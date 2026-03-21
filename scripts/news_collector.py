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
    # ── General cyber news ──────────────────────────────────────────────────────
    {"name": "krebs",            "url": "https://krebsonsecurity.com/feed/"},
    {"name": "bleepingcomputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "hackernews",       "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "schneier",         "url": "https://www.schneier.com/feed/atom/"},
    {"name": "darkreading",      "url": "https://www.darkreading.com/rss.xml"},
    {"name": "securityweek",     "url": "https://feeds.feedburner.com/securityweek"},
    {"name": "cyberscoop",       "url": "https://cyberscoop.com/feed/"},

    # ── Official advisories & vulnerabilities ───────────────────────────────────
    {"name": "cisa_alerts",      "url": "https://www.cisa.gov/cybersecurity-advisories/advisories.xml"},
    {"name": "sans_isc",         "url": "https://isc.sans.edu/rssfeed_full.xml"},
    {"name": "exploit_db",       "url": "https://www.exploit-db.com/rss.xml"},
    {"name": "github_advisories","url": "https://github.com/advisories.atom"},

    # ── Vendor threat research (TTP, campaigns, malware analysis) ───────────────
    {"name": "unit42",           "url": "https://unit42.paloaltonetworks.com/feed/"},
    {"name": "talos",            "url": "https://blog.talosintelligence.com/feeds/posts/default"},
    {"name": "mandiant",         "url": "https://www.mandiant.com/resources/rss.xml"},
    {"name": "securelist",       "url": "https://securelist.com/feed/"},
    {"name": "sophos_xops",      "url": "https://news.sophos.com/en-us/category/threat-research/feed/"},
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
