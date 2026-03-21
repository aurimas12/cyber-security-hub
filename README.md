# Cyber Security Intelligence Hub

Automated pipeline that collects cyber security news and CVEs, extracts vulnerabilities,
attack techniques, threat actors, incidents, and defensive strategies using Google Gemma AI.

## Architecture

```
RSS Feeds (16 sources)          NVD 2.0 API
        ↓                            ↓
[news_collector.py]        [nvd_api_collector.py]
        ↓                            ↓
              raw_articles table
                      ↓
           [article_parser.py]       ← Gemma 3-12B (Google AI Studio)
                      ↓
              parsed_articles table
                      ↓ (parallel)
[vuln_extractor.py]          → vulnerabilities table
[methodology_extractor.py]   → methodologies table
[strategy_extractor.py]      → strategies table
[threat_actor_extractor.py]  → threat_actors table
[incident_extractor.py]      → incidents table
```

Everything runs on GitHub Actions (cron every 6h). Data stored in Supabase.

## Setup

### 1. Supabase

Create a new Supabase project and run [supabase/schema.sql](supabase/schema.sql)
in the SQL Editor.

### 2. GitHub Secrets

Add these secrets to your repository
(Settings → Secrets and Variables → Actions):

| Secret | Where to get it |
|--------|----------------|
| `SUPABASE_URL` | Supabase → Project Settings → API → Project URL |
| `SUPABASE_SERVICE_KEY` | Supabase → Project Settings → API → `service_role` key |
| `GEMINI_API_KEY` | aistudio.google.com → Get API key |
| `NVD_API_KEY` | nvd.nist.gov/developers/request-an-api-key (optional, increases rate limits) |

### 3. Enable GitHub Actions

Push to GitHub and the pipeline will run automatically every 6 hours.
Trigger manually from Actions → Security Intelligence Pipeline → Run workflow.

## Scripts

| Script | Input | Output | API calls |
|--------|-------|--------|-----------|
| `news_collector.py` | RSS feeds | `raw_articles` | None |
| `nvd_api_collector.py` | NVD 2.0 API | `raw_articles` | None |
| `article_parser.py` | `raw_articles` (pending) | `parsed_articles` | Gemma 3-12B (1 per article) |
| `vuln_extractor.py` | `parsed_articles` (pending) | `vulnerabilities` | None |
| `methodology_extractor.py` | `parsed_articles` (pending) | `methodologies` | None |
| `strategy_extractor.py` | `parsed_articles` (pending) | `strategies` | None |
| `threat_actor_extractor.py` | `parsed_articles` (pending) | `threat_actors` | None |
| `incident_extractor.py` | `parsed_articles` (pending) | `incidents` | None |
| `backfill.py` | manual / daily cron | resets error rows | None |

## News Sources

**General cyber news**
- Krebs on Security
- BleepingComputer
- The Hacker News
- Schneier on Security
- Dark Reading
- SecurityWeek
- CyberScoop

**Official advisories**
- CISA Advisories
- SANS Internet Storm Center
- Exploit-DB
- GitHub Security Advisories
- NVD CVE (via NVD 2.0 API)

**Vendor threat research**
- Palo Alto Unit 42
- Cisco Talos
- Mandiant
- Kaspersky Securelist
- Sophos X-Ops
