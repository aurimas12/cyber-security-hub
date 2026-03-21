"""
nvd_api_collector.py
--------------------
Fetches CVE data from NVD 2.0 REST API and inserts into raw_articles.
Runs separately from news_collector (via GitHub Actions job).

Features:
- Fetches recent CVEs (configurable days, default 7)
- Handles pagination automatically
- Rate limiting to respect API limits
- Stores full NVD JSON in raw_content for downstream parsing

Rate Limits:
- No API Key: 6 requests/sec, 10,000/day
- With API Key: 26 requests/sec, 30,000/day
"""

import os
import time
import json
import requests
from datetime import datetime, timezone, timedelta
from supabase import create_client

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")  # Optional but recommended

# NVD 2.0 API Configuration
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limiting: 6 req/sec without key, 26 with key
REQUESTS_PER_SECOND = 26 if NVD_API_KEY else 6
REQUEST_DELAY = 1.0 / REQUESTS_PER_SECOND

# Default: fetch last 7 days of CVEs
DEFAULT_DAYS = 7


def get_date_range(days: int) -> tuple[str, str]:
    """Calculate ISO 8601 date range for API query."""
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)
    # NVD expects: YYYY-MM-DDTHH:MM:SS.SSSZ
    return (
        start_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        end_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    )


def fetch_cves(start_date: str, end_date: str, max_results: int = 2000) -> list[dict]:
    """
    Fetch CVEs from NVD API with pagination.
    
    Returns list of CVE objects with full data.
    """
    headers = {
        "Accept": "application/json"
    }
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    
    all_cves = []
    start_index = 0
    MAX_403_RETRIES = 5

    while True:
        params = {
            "pubStartDate": start_date,
            "pubEndDate": end_date,
            "resultsPerPage": min(2000, max_results - len(all_cves)),
            "startIndex": start_index
        }

        print(f"Fetching CVEs from index {start_index}...")

        retry_403 = 0
        while True:
            try:
                response = requests.get(
                    NVD_API_BASE,
                    params=params,
                    headers=headers,
                    timeout=30
                )

                # Handle rate limiting with a finite retry limit
                if response.status_code == 403:
                    retry_403 += 1
                    if retry_403 > MAX_403_RETRIES:
                        print(f"Rate limited (403) after {MAX_403_RETRIES} retries. Aborting.")
                        return all_cves
                    print(f"Rate limited (403), retry {retry_403}/{MAX_403_RETRIES}. Waiting 6 seconds...")
                    time.sleep(6)
                    continue

                response.raise_for_status()
                data = response.json()
                break

            except requests.exceptions.RequestException as e:
                print(f"Error fetching CVEs: {e}")
                return all_cves
        
        # Extract CVEs from response
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break
            
        for vuln in vulnerabilities:
            all_cves.append(vuln.get("cve", {}))
        
        # Check for more results
        total_results = data.get("totalResults", 0)
        if len(all_cves) >= total_results:
            break
            
        start_index += len(vulnerabilities)
        
        # Rate limit delay between requests
        time.sleep(REQUEST_DELAY)
    
    return all_cves


def parse_cve_data(cve: dict) -> dict:
    """
    Parse NVD CVE data into raw_articles format.
    
    Extracts:
    - CVE ID (title)
    - NVD detail URL
    - Published date
    - Full JSON in raw_content
    """
    cve_id = cve.get("id", "UNKNOWN")
    
    # Get published date
    published = cve.get("published", "")
    published_iso = None
    if published:
        try:
            # NVD format: 2024-01-15T00:00:00.000Z
            dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
            published_iso = dt.isoformat()
        except ValueError:
            pass
    
    # Build description from English description
    description = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    
    # Extract CVSS 3.1 metrics if available
    cvss_data = {}
    metrics = cve.get("metrics", {})
    cvss_v31 = metrics.get("cvssMetricV31", [])
    if cvss_v31:
        cvss_data = cvss_v31[0].get("cvssData", {})
    
    # Extract CWEs
    cwes = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("value", "").startswith("CWE-"):
                cwes.append(desc["value"])
    
    # Extract reference URLs with tags
    references = []
    for ref in cve.get("references", []):
        references.append({
            "url": ref.get("url", ""),
            "source": ref.get("source", ""),
            "tags": ref.get("tags", [])
        })
    
    # Build structured content for raw_content
    structured_content = {
        "cve_id": cve_id,
        "description": description,
        "published": published,
        "last_modified": cve.get("lastModified", ""),
        "vuln_status": cve.get("vulnStatus", ""),
        "cvss": cvss_data,
        "cwes": cwes,
        "references": references,
        "configurations": cve.get("configurations", [])
    }
    
    # Format URL as NVD detail page
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    
    # Title is CVE ID + severity if available
    title = cve_id
    if cvss_data.get("baseSeverity"):
        title = f"{cve_id} ({cvss_data['baseSeverity']})"
    
    return {
        "source_feed": "nvd_api",
        "title": title,
        "url": url,
        "published_at": published_iso,
        "raw_content": json.dumps(structured_content, indent=2),
        "status": "pending"
    }


def main():
    """Main entry point - fetch recent CVEs and store in raw_articles."""
    print(f"NVD API Collector starting...")
    print(f"API Key: {'Yes' if NVD_API_KEY else 'No (using default limits)'}")
    
    # Get date range
    days = int(os.environ.get("NVD_DAYS", DEFAULT_DAYS))
    start_date, end_date = get_date_range(days)
    print(f"Fetching CVEs from {start_date} to {end_date}")
    
    # Initialize Supabase client
    client = create_client(SUPABASE_URL, SUPABASE_KEY)
    
    # Fetch CVEs
    print("Fetching CVEs from NVD API...")
    cves = fetch_cves(start_date, end_date)
    print(f"Fetched {len(cves)} CVEs")
    
    if not cves:
        print("No CVEs found in date range")
        return
    
    # Parse into raw_articles format
    rows = []
    for cve in cves:
        try:
            row = parse_cve_data(cve)
            rows.append(row)
        except Exception as e:
            cve_id = cve.get("id", "UNKNOWN")
            print(f"Error parsing {cve_id}: {e}")
    
    if not rows:
        print("No valid CVE rows to insert")
        return
    
    print(f"Inserting {len(rows)} CVEs into raw_articles...")
    
    # Insert into Supabase (idempotent via URL unique constraint)
    result = (
        client.table("raw_articles")
        .upsert(rows, on_conflict="url", ignore_duplicates=True)
        .execute()
    )
    
    inserted = len(result.data) if result.data else 0
    print(f"Done. {inserted} new CVEs inserted (duplicates skipped)")


if __name__ == "__main__":
    main()