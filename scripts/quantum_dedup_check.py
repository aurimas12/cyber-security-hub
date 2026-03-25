"""
quantum_dedup_check.py
----------------------
Scans quantum_raw_articles for duplicate or near-duplicate articles.

Duplicate types detected:
  1. Exact URL duplicates (shouldn't exist due to UNIQUE constraint, sanity check)
  2. Normalized URL duplicates (same URL, different query params / trailing slash)
  3. Near-duplicate titles across different sources (difflib ratio >= threshold)

Does NOT modify the database — read-only report only.
"""

import os
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse, urlencode, parse_qsl
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]

# Titles with similarity >= this are flagged as near-duplicates
SIMILARITY_THRESHOLD = 0.80

# Query string params to strip before URL comparison
TRACKING_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term",
                   "utm_content", "ref", "source", "fbclid", "gclid"}


def normalize_url(url: str) -> str:
    """Strip tracking params and trailing slashes for comparison."""
    try:
        p = urlparse(url)
        clean_qs = urlencode(
            [(k, v) for k, v in parse_qsl(p.query) if k not in TRACKING_PARAMS]
        )
        normalized = p._replace(query=clean_qs, fragment="")
        return normalized.geturl().rstrip("/").lower()
    except Exception:
        return url.lower().rstrip("/")


def normalize_title(title: str) -> str:
    """Lowercase, strip punctuation for comparison."""
    return re.sub(r"[^\w\s]", "", title.lower()).strip()


def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def fetch_all_articles(db) -> list[dict]:
    """Fetch all articles, paginated."""
    all_rows = []
    page_size = 1000
    offset = 0
    while True:
        result = (
            db.table("quantum_raw_articles")
            .select("id, source_feed, title, url, published_at")
            .order("published_at", desc=True)
            .range(offset, offset + page_size - 1)
            .execute()
        )
        batch = result.data or []
        all_rows.extend(batch)
        if len(batch) < page_size:
            break
        offset += page_size
    return all_rows


def check_exact_url_duplicates(articles: list[dict]) -> int:
    seen = {}
    dupes = []
    for a in articles:
        url = a["url"]
        if url in seen:
            dupes.append((seen[url], a))
        else:
            seen[url] = a

    if dupes:
        print(f"\n[!] EXACT URL DUPLICATES: {len(dupes)} pairs found")
        for a, b in dupes:
            print(f"    ID {a['id']} vs {b['id']} — {a['url'][:80]}")
    else:
        print("\n[OK] No exact URL duplicates")
    return len(dupes)


def check_normalized_url_duplicates(articles: list[dict]) -> int:
    seen = {}
    dupes = []
    for a in articles:
        norm = normalize_url(a["url"])
        if norm in seen and seen[norm]["url"] != a["url"]:
            dupes.append((seen[norm], a))
        else:
            seen[norm] = a

    if dupes:
        print(f"\n[!] NORMALIZED URL DUPLICATES: {len(dupes)} pairs found")
        for a, b in dupes:
            print(f"    [{a['source_feed']}] {a['url'][:70]}")
            print(f"    [{b['source_feed']}] {b['url'][:70]}")
    else:
        print("[OK] No normalized URL duplicates")
    return len(dupes)


def check_near_duplicate_titles(articles: list[dict], threshold: float) -> int:
    """O(n²) comparison — fine for thousands of articles."""
    norm_titles = [(a, normalize_title(a["title"])) for a in articles]
    flagged = []

    for i in range(len(norm_titles)):
        a, ta = norm_titles[i]
        for j in range(i + 1, len(norm_titles)):
            b, tb = norm_titles[j]
            # Skip if same source (same feed often reposts similar titles)
            if a["source_feed"] == b["source_feed"]:
                continue
            score = similarity(ta, tb)
            if score >= threshold:
                flagged.append((score, a, b))

    flagged.sort(reverse=True, key=lambda x: x[0])

    if flagged:
        print(f"\n[!] NEAR-DUPLICATE TITLES (>= {threshold:.0%}): {len(flagged)} pairs found")
        for score, a, b in flagged[:50]:  # show top 50
            print(f"\n    Similarity: {score:.0%}")
            print(f"    [{a['source_feed']}] {a['title'][:90]}")
            print(f"    [{b['source_feed']}] {b['title'][:90]}")
        if len(flagged) > 50:
            print(f"\n    ... and {len(flagged) - 50} more")
    else:
        print(f"[OK] No near-duplicate titles found (threshold {threshold:.0%})")

    return len(flagged)


def main():
    db = create_client(SUPABASE_URL, SUPABASE_KEY)

    print("Fetching articles from quantum_raw_articles...")
    articles = fetch_all_articles(db)
    print(f"Total articles: {len(articles)}")

    exact     = check_exact_url_duplicates(articles)
    norm_url  = check_normalized_url_duplicates(articles)
    near_dup  = check_near_duplicate_titles(articles, SIMILARITY_THRESHOLD)

    print("\n── Summary ─────────────────────────────")
    print(f"  Exact URL duplicates:       {exact}")
    print(f"  Normalized URL duplicates:  {norm_url}")
    print(f"  Near-duplicate titles:      {near_dup}")
    print("────────────────────────────────────────")
    print("NOTE: This script is read-only. No data was modified.")


if __name__ == "__main__":
    main()
