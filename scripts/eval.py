"""
eval.py
-------
ONE JOB: Validate LLM predictions against real-world databases.

Checks:
  - MITRE ATT&CK technique IDs (methodologies table) → MITRE CTI GitHub
  - CVE IDs (vulnerabilities table) → NVD 2.0 API

Results stored in ai_validations table.
Runs after extract stage in the pipeline.
"""

import os
import re
import time
import requests
from supabase import create_client

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]
NVD_API_KEY  = os.environ.get("NVD_API_KEY", "")

# MITRE ATT&CK Enterprise STIX bundle (official source)
MITRE_CTI_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# How many recent rows to validate per run (avoid re-checking everything)
BATCH_SIZE = 100

# Seconds between NVD API calls (respect rate limits)
NVD_DELAY = 0.4 if NVD_API_KEY else 6.0


# ── MITRE ──────────────────────────────────────────────────────────────────────

def fetch_valid_mitre_ids() -> set[str]:
    """Download MITRE ATT&CK STIX bundle and extract all valid technique IDs."""
    print("Fetching MITRE ATT&CK technique list from GitHub...")
    response = requests.get(MITRE_CTI_URL, timeout=120)
    response.raise_for_status()

    valid_ids: set[str] = set()
    for obj in response.json().get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        # Skip deprecated / revoked techniques
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id", "")
                if ext_id.startswith("T"):
                    valid_ids.add(ext_id)

    print(f"Loaded {len(valid_ids)} valid MITRE technique IDs")
    return valid_ids


def mitre_id_format_ok(mitre_id: str) -> bool:
    """Quick regex check before hitting the set — catches obvious garbage."""
    return bool(re.fullmatch(r"T\d{4}(\.\d{3})?", mitre_id))


# ── NVD ────────────────────────────────────────────────────────────────────────

def check_cve_exists(cve_id: str) -> bool:
    """Return True if the CVE ID exists in NVD."""
    headers = {"Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        response = requests.get(
            NVD_API_BASE,
            params={"cveId": cve_id},
            headers=headers,
            timeout=15,
        )
        if response.status_code == 200:
            return response.json().get("totalResults", 0) > 0
    except requests.exceptions.RequestException as e:
        print(f"  NVD API error for {cve_id}: {e}")
    return False


# ── Already validated helpers ──────────────────────────────────────────────────

def already_validated_ids(db, source_table: str, field_type: str) -> set[str]:
    """Return source_row_ids that have already been validated."""
    result = (
        db.table("ai_validations")
        .select("source_row_id")
        .eq("source_table", source_table)
        .eq("field_type", field_type)
        .execute()
    )
    return {row["source_row_id"] for row in (result.data or [])}


# ── Main validation routines ───────────────────────────────────────────────────

def validate_mitre_ids(db, valid_mitre_ids: set[str]) -> dict:
    """Check methodologies.mitre_technique_id against MITRE ATT&CK."""
    done_ids = already_validated_ids(db, "methodologies", "mitre_id")

    rows = (
        db.table("methodologies")
        .select("id, parsed_article_id, mitre_technique_id")
        .not_.is_("mitre_technique_id", "null")
        .limit(BATCH_SIZE)
        .execute()
        .data
    ) or []

    # Filter out already validated
    rows = [r for r in rows if r["id"] not in done_ids]

    stats = {"total": 0, "valid": 0, "invalid": 0, "bad_format": 0}
    validation_rows = []

    for row in rows:
        mitre_id = row["mitre_technique_id"]
        stats["total"] += 1

        if not mitre_id_format_ok(mitre_id):
            is_valid = False
            stats["bad_format"] += 1
            print(f"  [MITRE] BAD FORMAT: {mitre_id}")
        elif mitre_id in valid_mitre_ids:
            is_valid = True
            stats["valid"] += 1
        else:
            is_valid = False
            stats["invalid"] += 1
            print(f"  [MITRE] NOT FOUND: {mitre_id}")

        validation_rows.append({
            "parsed_article_id": row["parsed_article_id"],
            "source_table": "methodologies",
            "source_row_id": row["id"],
            "field_type": "mitre_id",
            "predicted_value": mitre_id,
            "is_valid": is_valid,
        })

    if validation_rows:
        db.table("ai_validations").insert(validation_rows).execute()

    return stats


def validate_cve_ids(db) -> dict:
    """Check vulnerabilities.cve_id against NVD API."""
    done_ids = already_validated_ids(db, "vulnerabilities", "cve_id")

    rows = (
        db.table("vulnerabilities")
        .select("id, parsed_article_id, cve_id")
        .not_.is_("cve_id", "null")
        .limit(BATCH_SIZE)
        .execute()
        .data
    ) or []

    rows = [r for r in rows if r["id"] not in done_ids]

    stats = {"total": 0, "valid": 0, "invalid": 0, "bad_format": 0}
    validation_rows = []

    cve_format = re.compile(r"CVE-\d{4}-\d{4,7}")

    for i, row in enumerate(rows):
        cve_id = row["cve_id"]
        stats["total"] += 1

        if not cve_format.fullmatch(cve_id):
            is_valid = False
            stats["bad_format"] += 1
            print(f"  [CVE] BAD FORMAT: {cve_id}")
        else:
            is_valid = check_cve_exists(cve_id)
            if is_valid:
                stats["valid"] += 1
            else:
                stats["invalid"] += 1
                print(f"  [CVE] NOT FOUND: {cve_id}")

            # Rate limit between NVD calls
            if i < len(rows) - 1:
                time.sleep(NVD_DELAY)

        validation_rows.append({
            "parsed_article_id": row["parsed_article_id"],
            "source_table": "vulnerabilities",
            "source_row_id": row["id"],
            "field_type": "cve_id",
            "predicted_value": cve_id,
            "is_valid": is_valid,
        })

    if validation_rows:
        db.table("ai_validations").insert(validation_rows).execute()

    return stats


# ── Summary report ─────────────────────────────────────────────────────────────

def print_summary(db):
    """Print overall accuracy stats from ai_validations."""
    result = db.table("ai_validations").select("field_type, is_valid").execute()
    rows = result.data or []

    for field_type in ("mitre_id", "cve_id"):
        subset = [r for r in rows if r["field_type"] == field_type]
        if not subset:
            continue
        total = len(subset)
        valid = sum(1 for r in subset if r["is_valid"])
        pct = (valid / total * 100) if total else 0
        print(f"  {field_type}: {valid}/{total} valid ({pct:.1f}% accuracy)")


def main():
    db = create_client(SUPABASE_URL, SUPABASE_KEY)

    print("=== AI Prediction Validator ===")

    # ── MITRE ATT&CK ──
    valid_mitre_ids = fetch_valid_mitre_ids()
    mitre_stats = validate_mitre_ids(db, valid_mitre_ids)
    print(f"MITRE checked: {mitre_stats['total']} | "
          f"valid: {mitre_stats['valid']} | "
          f"invalid: {mitre_stats['invalid']} | "
          f"bad format: {mitre_stats['bad_format']}")

    # ── CVE / NVD ──
    print(f"\nValidating CVE IDs via NVD API...")
    cve_stats = validate_cve_ids(db)
    print(f"CVE checked: {cve_stats['total']} | "
          f"valid: {cve_stats['valid']} | "
          f"invalid: {cve_stats['invalid']} | "
          f"bad format: {cve_stats['bad_format']}")

    # ── Overall accuracy across all history ──
    print("\n=== Overall LLM Accuracy (all time) ===")
    print_summary(db)
    print("\nDone.")


if __name__ == "__main__":
    main()
