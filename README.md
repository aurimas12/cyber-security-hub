# Cyber Security Intelligence Hub

Automated pipeline that collects cyber security news, extracts vulnerabilities,
attack techniques, and defensive strategies using Claude AI.

## Architecture

```
RSS Feeds (8 sources)
    ↓
[news_collector.py]      → raw_articles table
    ↓
[article_parser.py]      → parsed_articles table (1 Claude call per article)
    ↓ (parallel)
[vuln_extractor.py]      → vulnerabilities table
[methodology_extractor.py] → methodologies table
[strategy_extractor.py]  → strategies table
```

Everything runs on GitHub Actions (cron every 6h). Data stored in Supabase.

## Setup

### 1. Supabase

Create a new Supabase project and run [supabase/schema.sql](supabase/schema.sql)
in the SQL Editor.

### 2. GitHub Secrets

Add these three secrets to your repository
(Settings → Secrets and Variables → Actions):

| Secret | Where to get it |
|--------|----------------|
| `SUPABASE_URL` | Supabase → Project Settings → API → Project URL |
| `SUPABASE_SERVICE_KEY` | Supabase → Project Settings → API → `service_role` key |
| `ANTHROPIC_API_KEY` | console.anthropic.com |

### 3. Enable GitHub Actions

Push to GitHub and the pipeline will run automatically every 6 hours.
Trigger manually from Actions → Security Intelligence Pipeline → Run workflow.

## Scripts

| Script | Input | Output | API calls |
|--------|-------|--------|-----------|
| `news_collector.py` | RSS feeds | `raw_articles` | None |
| `article_parser.py` | `raw_articles` (pending) | `parsed_articles` | Claude (1 per article) |
| `vuln_extractor.py` | `parsed_articles` (pending) | `vulnerabilities` | None |
| `methodology_extractor.py` | `parsed_articles` (pending) | `methodologies` | None |
| `strategy_extractor.py` | `parsed_articles` (pending) | `strategies` | None |
| `backfill.py` | manual | resets error rows | None |

## News Sources

- Krebs on Security
- BleepingComputer
- The Hacker News
- CISA Advisories
- Schneier on Security
- Dark Reading
- SANS Internet Storm Center
- NVD CVE Feed
