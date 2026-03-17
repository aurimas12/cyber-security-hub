"""
article_parser.py
-----------------
ONE JOB: Read pending raw_articles, call Gemma3-12B via Google Gemini API,
store structured JSON analysis in parsed_articles.

Model: gemma-3-12b-it (free tier via Google AI Studio)
Free tier limits:
  - 30 RPM  (requests per minute)
  - 1,000 RPD (requests per day)
  - 8,192 tokens input context

Rate limiting and retry with exponential backoff are handled automatically.
"""

import os
import re
import json
import time
import random
from google import genai
from google.genai import types
from google.api_core.exceptions import ResourceExhausted, ServiceUnavailable, GoogleAPIError
from supabase import create_client

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]
GEMINI_KEY   = os.environ["GEMINI_API_KEY"]
MODEL        = "gemma-3-12b-it"

# ── Limits ─────────────────────────────────────────────────────────────────────
BATCH_SIZE        = 20    # articles per run (80/day at 4 runs → well under 1000 RPD)
DELAY_BETWEEN_REQ = 2.5   # seconds between requests → max 24 RPM (safe under 30 RPM)
MAX_RETRIES       = 4     # max attempts per article
CONTENT_CHAR_LIMIT = 5000 # ~1250 tokens, leaves room for prompt + response

PROMPT = """Analyze this cybersecurity article and return ONLY a valid JSON object with exactly these keys.
No markdown, no explanation, just raw JSON.

{{
  "summary": "2-3 sentence summary",
  "vulnerabilities": [
    {{
      "cve_id": "CVE-YYYY-NNNNN or null",
      "description": "what the vulnerability is",
      "affected_products": ["product1"],
      "severity": "critical|high|medium|low or null",
      "cvss_score": 9.8,
      "patch_available": true,
      "patch_url": "url or null"
    }}
  ],
  "techniques": [
    {{
      "name": "technique name",
      "mitre_id": "T1234.001 or null",
      "mitre_tactic": "Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact or null",
      "description": "how it works",
      "threat_actor": "group name or null"
    }}
  ],
  "recommendations": [
    {{
      "text": "what to do",
      "category": "patch|config|monitoring|training|architecture",
      "priority": "immediate|short-term|long-term",
      "applies_to": ["sysadmin"],
      "related_cves": ["CVE-YYYY-NNNNN"]
    }}
  ]
}}

Return empty arrays [] if nothing found for that category.

Article title: {title}
Article content:
{content}"""


def clean_json(raw: str) -> str:
    """Strip markdown code fences if model adds them."""
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?\n?", "", raw)
    raw = re.sub(r"\n?```$", "", raw)
    return raw.strip()


def call_gemma_with_retry(client: genai.Client, title: str, content: str) -> dict:
    """
    Call Gemma3-12B with exponential backoff on rate limit / server errors.

    Retry schedule (seconds): 5, 10, 20, 40 (+ jitter)
    """
    prompt = PROMPT.format(title=title, content=content[:CONTENT_CHAR_LIMIT])

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = client.models.generate_content(
                model=MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.1,
                    max_output_tokens=2048,
                ),
            )
            return json.loads(clean_json(response.text))

        except json.JSONDecodeError:
            # Model returned non-JSON - no point retrying, mark error
            raise

        except ResourceExhausted:
            # 429 - rate limit hit
            if attempt == MAX_RETRIES:
                raise
            wait = (2 ** attempt) * 5 + random.uniform(0, 2)
            print(f"  Rate limit hit (attempt {attempt}/{MAX_RETRIES}), waiting {wait:.1f}s...")
            time.sleep(wait)

        except ServiceUnavailable:
            # 503 - transient server error
            if attempt == MAX_RETRIES:
                raise
            wait = (2 ** attempt) * 3 + random.uniform(0, 2)
            print(f"  Service unavailable (attempt {attempt}/{MAX_RETRIES}), waiting {wait:.1f}s...")
            time.sleep(wait)

        except GoogleAPIError:
            # Other API errors - don't retry
            raise


def check_daily_budget(db, limit: int = 1000) -> int:
    """
    Count how many articles were parsed today.
    Stop if we're close to the 1000 RPD limit.
    Returns remaining budget.
    """
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    result = (
        db.table("parsed_articles")
        .select("id", count="exact")
        .gte("parsed_at", today.isoformat())
        .execute()
    )
    used = result.count or 0
    remaining = limit - used
    print(f"Daily budget: {used}/{limit} used, {remaining} remaining")
    return remaining


def main():
    db = create_client(SUPABASE_URL, SUPABASE_KEY)
    client = genai.Client(api_key=GEMINI_KEY)

    # Guard against hitting daily limit
    remaining_budget = check_daily_budget(db, limit=950)  # 950 = safe margin under 1000
    if remaining_budget <= 0:
        print("Daily API budget exhausted. Skipping run.")
        return

    effective_batch = min(BATCH_SIZE, remaining_budget)

    articles = (
        db.table("raw_articles")
        .select("id, title, url, published_at, raw_content")
        .eq("status", "pending")
        .limit(effective_batch)
        .execute()
        .data
    )

    print(f"Model: {MODEL}")
    print(f"Found {len(articles)} pending articles (batch capped at {effective_batch})")

    for i, article in enumerate(articles):
        article_id = article["id"]
        print(f"[{i+1}/{len(articles)}] {article['title'][:75]}")

        db.table("raw_articles").update({"status": "processing"}).eq("id", article_id).execute()

        try:
            analysis = call_gemma_with_retry(client, article["title"], article["raw_content"] or "")

            db.table("parsed_articles").insert({
                "raw_article_id": article_id,
                "title": article["title"],
                "url": article["url"],
                "published_at": article["published_at"],
                "summary": analysis.get("summary"),
                "claude_analysis": analysis,
            }).execute()

            db.table("raw_articles").update({"status": "parsed"}).eq("id", article_id).execute()
            print(f"  OK - {len(analysis.get('vulnerabilities', []))} vulns | "
                  f"{len(analysis.get('techniques', []))} techniques | "
                  f"{len(analysis.get('recommendations', []))} recs")

        except json.JSONDecodeError as e:
            db.table("raw_articles").update({
                "status": "error",
                "error_message": f"JSON parse error: {e}"
            }).eq("id", article_id).execute()
            print(f"  ERROR (JSON): {e}")

        except Exception as e:
            db.table("raw_articles").update({
                "status": "error",
                "error_message": str(e)[:500]
            }).eq("id", article_id).execute()
            print(f"  ERROR: {type(e).__name__}: {e}")

        # Rate limit: wait between requests to stay under 30 RPM
        if i < len(articles) - 1:
            time.sleep(DELAY_BETWEEN_REQ)

    print("Done.")


if __name__ == "__main__":
    main()
