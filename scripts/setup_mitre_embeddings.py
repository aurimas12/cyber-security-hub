"""
setup_mitre_embeddings.py
--------------------------
ONE-TIME SETUP: Fetch all MITRE ATT&CK techniques, generate embeddings
using fastembed (offline, no API needed), store in Supabase mitre_techniques.

Run once before first pipeline run:
  python scripts/setup_mitre_embeddings.py

Re-run periodically to pick up new ATT&CK releases (~quarterly).
"""

import os
import requests
from dotenv import load_dotenv
from fastembed import TextEmbedding
from supabase import create_client

load_dotenv()
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ.get("SUPABASE_KEY") or os.environ["SUPABASE_SERVICE_KEY"]

# BAAI/bge-base-en-v1.5: 768 dims, ~220MB ONNX, runs on CPU, no API needed
EMBED_MODEL = "BAAI/bge-base-en-v1.5"
MITRE_CTI_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
BATCH_SIZE = 100   # fastembed handles batching internally


def fetch_mitre_techniques() -> list[dict]:
    """Download MITRE ATT&CK STIX bundle and extract active techniques."""
    print("Fetching MITRE ATT&CK STIX bundle (~50MB)...")
    response = requests.get(MITRE_CTI_URL, timeout=120)
    response.raise_for_status()

    techniques = []
    for obj in response.json().get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break

        if not technique_id or not technique_id.startswith("T"):
            continue

        kill_chain = obj.get("kill_chain_phases", [])
        tactic = (
            kill_chain[0].get("phase_name", "unknown").replace("-", " ").title()
            if kill_chain else "Unknown"
        )

        name = obj.get("name", "")
        description = obj.get("description", "")[:600]
        embed_text = f"{name}. Tactic: {tactic}. {description}"

        techniques.append({
            "technique_id": technique_id,
            "name":         name,
            "tactic":       tactic,
            "description":  description,
            "embed_text":   embed_text,
        })

    print(f"Found {len(techniques)} active techniques")
    return techniques


def main():
    db = create_client(SUPABASE_URL, SUPABASE_KEY)

    techniques = fetch_mitre_techniques()

    print(f"Loading embedding model: {EMBED_MODEL} (first run downloads ~220MB)...")
    model = TextEmbedding(EMBED_MODEL)

    texts = [t["embed_text"] for t in techniques]
    print(f"Generating embeddings for {len(texts)} techniques...")
    embeddings = list(model.embed(texts))

    rows = []
    for technique, embedding in zip(techniques, embeddings):
        rows.append({
            "technique_id": technique["technique_id"],
            "name":         technique["name"],
            "tactic":       technique["tactic"],
            "description":  technique["description"],
            "embedding":    embedding.tolist(),
        })

    print(f"Inserting {len(rows)} techniques into Supabase...")
    chunk = 100
    for i in range(0, len(rows), chunk):
        db.table("mitre_techniques").upsert(
            rows[i:i + chunk],
            on_conflict="technique_id"
        ).execute()
        print(f"  Inserted {min(i + chunk, len(rows))}/{len(rows)}")

    print(f"Done. {len(rows)} MITRE techniques stored with embeddings.")


if __name__ == "__main__":
    main()
