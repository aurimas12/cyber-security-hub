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
from google.genai import types, errors as genai_errors
from fastembed import TextEmbedding
from supabase import create_client

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]
GEMINI_KEY   = os.environ["GEMINI_API_KEY"]
MODEL        = "gemma-3-12b-it"
EMBED_MODEL  = "BAAI/bge-base-en-v1.5"   # 768 dims, same as setup_mitre_embeddings.py

# ── Limits ─────────────────────────────────────────────────────────────────────
BATCH_SIZE        = 20    # articles per run (80/day at 4 runs → well under 1000 RPD)
DELAY_BETWEEN_REQ = 2.5   # seconds between requests → max 24 RPM (safe under 30 RPM)
MAX_RETRIES       = 4     # max attempts per article
CONTENT_CHAR_LIMIT = 6000 # ~1500 tokens, leaves room for prompt + response

# Valid enum values — kept separate so the schema stays readable
MITRE_TACTICS = (
    "Initial Access|Execution|Persistence|Privilege Escalation|"
    "Defense Evasion|Credential Access|Discovery|Lateral Movement|"
    "Collection|Command and Control|Exfiltration|Impact"
)

SYSTEM_PROMPT = """You are a senior cybersecurity threat intelligence analyst with deep expertise in the MITRE ATT&CK framework, CVE analysis, and threat actor profiling.

Your only job is to read cybersecurity articles and return a structured JSON intelligence report. You never explain your reasoning, never add prose, and never output anything other than a single valid JSON object.

OUTPUT RULES:
- Return ONLY a raw JSON object. No markdown fences, no comments, no explanation.
- Only extract facts explicitly stated or strongly implied in the article. Never fabricate or infer beyond what is written.
- For MITRE technique IDs: you will be given a list of candidate techniques retrieved from the ATT&CK database. Pick the best match from that list. If NONE of the candidates fit, set mitre_id to null, set needs_review to true, and write your best guess in mitre_suggested (even if uncertain).
- For missing scalar fields: use null. For missing arrays: use [].

FIELD CONSTRAINTS (you must follow these exactly):
- severity: one of: critical, high, medium, low — or null
- cvss_score: float 0.0–10.0 (e.g. 9.8) — or null
- mitre_id: format T1234 or T1234.001 — or null if uncertain
- mitre_tactic: one of: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact — or null
- category: one of: patch, config, monitoring, training, architecture
- priority: one of: immediate, short-term, long-term
- applies_to: array from: sysadmin, developer, security-team, network-admin, management
- motivation: one of: espionage, financial, hacktivism, unknown
- sector: one of: healthcare, finance, government, energy, technology, education, critical-infrastructure, other
- attack_type: one of: ransomware, phishing, supply-chain, zero-day, ddos, data-breach, other

REQUIRED OUTPUT STRUCTURE:
{
  "summary": "2-3 sentence summary of the article",
  "vulnerabilities": [
    {
      "cve_id": "CVE-YYYY-NNNNN or null",
      "description": "what the vulnerability is and how it can be exploited",
      "affected_products": ["vendor product version"],
      "severity": "critical",
      "cvss_score": 9.8,
      "patch_available": true,
      "patch_url": "url or null"
    }
  ],
  "techniques": [
    {
      "name": "exact MITRE technique name or descriptive name if not in ATT&CK",
      "mitre_id": "T1566.001 or null — MUST be from the candidate list provided",
      "mitre_tactic": "Initial Access or null",
      "description": "how the technique was used in this specific article",
      "threat_actor": "group name or null",
      "needs_review": false,
      "mitre_suggested": "null — only fill if needs_review is true, write your best guess here"
    }
  ],
  "recommendations": [
    {
      "text": "specific actionable recommendation",
      "category": "patch",
      "priority": "immediate",
      "applies_to": ["sysadmin", "security-team"],
      "related_cves": ["CVE-YYYY-NNNNN"]
    }
  ],
  "threat_actors": [
    {
      "name": "official group name",
      "aliases": ["alias1", "alias2"],
      "origin_country": "country or null",
      "targeted_sectors": ["government", "finance"],
      "motivation": "espionage"
    }
  ],
  "incidents": [
    {
      "organization": "victim org name or null",
      "sector": "government",
      "attack_type": "ransomware",
      "data_compromised": ["credentials", "PII"],
      "incident_date": "YYYY-MM-DD or null"
    }
  ]
}

EXAMPLE — article about a North Korean phishing campaign:
{
  "summary": "Lazarus Group conducted a spear-phishing campaign targeting South Korean defense contractors. Attackers delivered malicious Office documents that deployed a custom backdoor via DLL side-loading. No CVEs were associated with this campaign.",
  "vulnerabilities": [],
  "techniques": [
    {
      "name": "Spear Phishing Attachment",
      "mitre_id": "T1566.001",
      "mitre_tactic": "Initial Access",
      "description": "Targeted emails with malicious Office documents containing embedded macros were sent to defense sector employees.",
      "threat_actor": "Lazarus Group"
    },
    {
      "name": "DLL Side-Loading",
      "mitre_id": "T1574.002",
      "mitre_tactic": "Defense Evasion",
      "description": "A legitimate signed binary loaded a malicious DLL from the same directory to bypass application whitelisting controls.",
      "threat_actor": "Lazarus Group"
    }
  ],
  "recommendations": [
    {
      "text": "Disable Office macros by default and enforce macro signing policies across all endpoints.",
      "category": "config",
      "priority": "immediate",
      "applies_to": ["sysadmin", "security-team"],
      "related_cves": []
    },
    {
      "text": "Monitor for unsigned DLL loads from user-writable directories using EDR telemetry.",
      "category": "monitoring",
      "priority": "short-term",
      "applies_to": ["security-team"],
      "related_cves": []
    }
  ],
  "threat_actors": [
    {
      "name": "Lazarus Group",
      "aliases": ["Hidden Cobra", "ZINC", "APT38"],
      "origin_country": "North Korea",
      "targeted_sectors": ["government", "technology"],
      "motivation": "espionage"
    }
  ],
  "incidents": [
    {
      "organization": null,
      "sector": "government",
      "attack_type": "phishing",
      "data_compromised": ["intellectual property"],
      "incident_date": null
    }
  ]
}"""

USER_PROMPT = """Analyze the following cybersecurity article and return a JSON intelligence report in the exact structure shown in your instructions.

MITRE ATT&CK CANDIDATE TECHNIQUES (retrieved from ATT&CK database for this article):
{rag_candidates}
IMPORTANT: For each technique you identify, select mitre_id ONLY from the candidates above.
If none of the candidates fit a behavior you found, set mitre_id to null, needs_review to true,
and write your best guess in mitre_suggested.

Article title: {title}

Article content:
{content}"""


_embed_model: TextEmbedding | None = None

def get_embed_model() -> TextEmbedding:
    """Load fastembed model once and reuse (lazy init)."""
    global _embed_model
    if _embed_model is None:
        print("  Loading embedding model (first run may download ~220MB)...")
        _embed_model = TextEmbedding(EMBED_MODEL)
    return _embed_model


def get_rag_candidates(db, text: str, top_k: int = 5) -> list[dict]:
    """
    Embed article text and retrieve top-K semantically similar MITRE techniques.
    Returns [] if mitre_techniques table is empty or on any error.
    """
    try:
        model = get_embed_model()
        embedding = list(model.embed([text[:2000]]))[0].tolist()

        result = db.rpc("match_mitre_techniques", {
            "query_embedding": embedding,
            "match_count": top_k,
        }).execute()

        return result.data or []

    except Exception as e:
        print(f"  RAG lookup failed (continuing without candidates): {e}")
        return []


def format_rag_candidates(candidates: list[dict]) -> str:
    """Format RAG candidates as a readable list for the prompt."""
    if not candidates:
        return "(No candidates retrieved — mitre_techniques table may be empty)"
    lines = []
    for c in candidates:
        lines.append(f"  • {c['technique_id']} | {c['name']} | {c['tactic']}")
    return "\n".join(lines)


def clean_json(raw: str) -> str:
    """Strip markdown code fences if model adds them."""
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?\n?", "", raw)
    raw = re.sub(r"\n?```$", "", raw)
    return raw.strip()


def call_gemma_with_retry(
    client: genai.Client,
    title: str,
    content: str,
    rag_candidates_text: str = "",
) -> dict:
    """
    Call Gemma3-12B with exponential backoff on rate limit / server errors.

    Retry schedule (seconds): 5, 10, 20, 40 (+ jitter)
    """
    user_message = USER_PROMPT.format(
        title=title,
        content=content[:CONTENT_CHAR_LIMIT],
        rag_candidates=rag_candidates_text,
    )

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = client.models.generate_content(
                model=MODEL,
                contents=user_message,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    temperature=0.1,
                    max_output_tokens=2048,
                ),
            )
            return json.loads(clean_json(response.text))

        except json.JSONDecodeError:
            # Model returned non-JSON — retry up to MAX_RETRIES, then give up
            if attempt == MAX_RETRIES:
                raise
            print(f"  JSON parse failed (attempt {attempt}/{MAX_RETRIES}), retrying...")
            time.sleep(2)

        except genai_errors.ClientError as e:
            # 429 rate limit or other 4xx
            if attempt == MAX_RETRIES or "429" not in str(e):
                raise
            wait = (2 ** attempt) * 5 + random.uniform(0, 2)
            print(f"  Rate limit hit (attempt {attempt}/{MAX_RETRIES}), waiting {wait:.1f}s...")
            time.sleep(wait)

        except genai_errors.ServerError:
            # 503 or other 5xx - transient
            if attempt == MAX_RETRIES:
                raise
            wait = (2 ** attempt) * 3 + random.uniform(0, 2)
            print(f"  Server error (attempt {attempt}/{MAX_RETRIES}), waiting {wait:.1f}s...")
            time.sleep(wait)


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
    client = genai.Client(api_key=GEMINI_KEY, http_options={"api_version": "v1"})

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
            content = article["raw_content"] or ""

            # RAG: find top-5 MITRE candidates before calling Gemma
            candidates = get_rag_candidates(db, f"{article['title']} {content}")
            candidates_text = format_rag_candidates(candidates)
            candidate_ids = [c["technique_id"] for c in candidates]
            print(f"  RAG: {len(candidates)} candidates → "
                  + ", ".join(candidate_ids) if candidate_ids else "  RAG: none")

            analysis = call_gemma_with_retry(
                client, article["title"], content, candidates_text
            )

            # Store RAG candidates in ai_analysis for review_queue traceability
            analysis["rag_candidates"] = candidate_ids

            db.table("parsed_articles").insert({
                "raw_article_id": article_id,
                "title": article["title"],
                "url": article["url"],
                "published_at": article["published_at"],
                "summary": analysis.get("summary"),
                "ai_analysis": analysis,
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
