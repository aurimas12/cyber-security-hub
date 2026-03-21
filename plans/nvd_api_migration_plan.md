# NVD RSS → NVD 2.0 API Migration Plan

## Current State

### NVD RSS Implementation
- **URL**: `https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml`
- **Format**: XML
- **Issues**: 
  - RSS feed is deprecated
  - Limited data fields
  - No structured CVSS data

### Current Data Flow
```
NVD RSS Feed (news_collector.py)
    ↓
raw_articles table (source_feed: "nvd_cve")
    ↓
article_parser.py (Gemini/Gemma3)
    ↓
parsed_articles (ai_analysis.vulnerabilities[])
    ↓
vuln_extractor.py → vulnerabilities table
```

---

## NVD 2.0 API Specification

### API Endpoint
```
Base URL: https://services.nvd.nist.gov/rest/json/cves/2.0
```

### Query Parameters
| Parameter | Description |
|-----------|-------------|
| `pubStartDate` | Published date range start (ISO 8601) |
| `pubEndDate` | Published date range end (ISO 8601) |
| `lastModStartDate` | Last modified start |
| `lastModEndDate` | Last modified end |
| `cvssV3Severity` | CRITICAL, HIGH, MEDIUM, LOW |
| `cweId` | CWE identifier |
| `cpeName` | CPE match string |
| `keywordSearch` | Text search |
| `resultsPerPage` | Max 2000 |
| `startIndex` | Pagination offset |

### Rate Limits (2024+)
| Tier | Requests/sec | Daily |
|------|--------------|-------|
| No API Key | 6 | 10,000 |
| Registered (free) | 26 | 30,000 |
| Organizational | 26+ | 100,000+ |

### Available Data Fields (NVD 2.0)
```json
{
  "cve": {
    "id": "CVE-2024-12345",
    "descriptions": [
      { "lang": "en", "value": "..." }
    ],
    "published": "2024-01-15T00:00:00.000Z",
    "lastModified": "2024-01-20T00:00:00.000Z",
    "vulnStatus": "Modified",
    "metrics": {
      "cvssMetricV31": [
        {
          "cvssData": {
            "baseScore": 9.8,
            "baseSeverity": "CRITICAL",
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "NONE",
            "userInteraction": "NONE",
            "scope": "UNCHANGED",
            "confidentialityImpact": "HIGH",
            "integrityImpact": "HIGH",
            "availabilityImpact": "HIGH"
          }
        }
      ]
    },
    "weaknesses": [
      {
        "description": [{ "value": "CWE-79" }]
      }
    ],
    "configurations": [...],
    "references": [
      {
        "url": "https://...",
        "source": "cve.org",
        "tags": ["Patch", "Vendor Advisory"]
      }
    ],
    "cpe": [...]
  }
}
```

---

## Migration Architecture

### Option 1: Separate NVD Collector (Recommended)
```python
# New script: nvd_api_collector.py
# Separate from news_collector.py for clarity

def main():
    # Option A: Fetch recent CVEs (last 7 days)
    recent_cves = fetch_recent_cves(days=7)
    
    # Option B: Fetch by date range
    cves = fetch_cves_by_date(start_date, end_date)
    
    # Option C: Fetch specific CVE IDs
    cves = fetch_cves_by_ids(["CVE-2024-12345", ...])
    
    # Store in raw_articles with special handling
    store_nvd_cves(cves)
```

### Option 2: Hybrid Approach
- Keep RSS for other feeds
- Add NVD API as separate collector
- Sync NVD data separately

---

## Implementation Steps

### Step 1: Add NVD API Key to GitHub Secrets
- Register at https://nvd.nist.gov/developers/request-an-api-key
- Add `NVD_API_KEY` to GitHub Secrets

### Step 2: Create nvd_api_collector.py
```python
# scripts/nvd_api_collector.py

# Features:
# - Fetch CVEs from last N days
# - Handle pagination
# - Rate limiting (respect API limits)
# - Store with source_feed = "nvd_api"
# - Parse CVSS 3.1/3.0 data
# - Extract CPEs, references, CWEs
```

### Step 3: Update Pipeline
- Add new job: `nvd_collect`
- Run separately from main news_collector
- More frequent updates possible (e.g., every 2 hours)

### Step 4: Update Schema (Optional)
- Add new table: `nvd_cves` for raw NVD data
- Or enhance `vulnerabilities` table with new fields

---

## Data Field Mapping

| NVD 2.0 Field | Current Schema Field | Notes |
|---------------|---------------------|-------|
| cve.id | cve_id | Direct mapping |
| descriptions[].value | vuln_description | English only |
| published | (new) | publication date |
| metrics.cvssMetricV31[].cvssData.baseScore | cvss_score | Float |
| metrics.cvssMetricV31[].cvssData.baseSeverity | severity | CRITICAL/HIGH/MEDIUM/LOW |
| metrics.cvssMetricV31[].cvssData.attackVector | (new) | NETWORK/ADJACENT/LOCAL/PHYSICAL |
| weaknesses[].description[].value | (new) | CWE-XXX |
| references[].url | patch_url | Filter by "Patch" tag |
| references[].source | (new) | Reference source |
| configurations.nodes.cpeMatch | affected_products | CPE strings |

---

## Benefits of Migration

1. **Real-time data** - No more RSS delay
2. **More fields** - CVSS 3.1, CWEs, CPEs, references
3. **Structured data** - JSON vs XML parsing
4. **Rate limits** - With API key: 30,000+ requests/day
5. **Historical data** - Can query any date range
6. **Filtering** - Can filter by severity, CWE, CPE

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| API key rate limits | Start with free tier, upgrade if needed |
| API downtime | Cache last known state, retry logic |
| Breaking changes | Version pin, error logging |
| Cost | Free tier sufficient for most use cases |

---

## Next Steps

1. [ ] Register for NVD API key
2. [ ] Add NVD_API_KEY to GitHub Secrets
3. [ ] Create scripts/nvd_api_collector.py
4. [ ] Update .github/workflows/pipeline.yml
5. [ ] Test with recent CVEs
6. [ ] Monitor API usage and adjust frequency

---

## Timeline Estimate

- **Planning**: Done
- **Implementation**: 2-3 hours
- **Testing**: 1 hour
- **Total**: 3-4 hours
