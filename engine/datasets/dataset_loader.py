"""
Dataset Loader Module

Reads the reference datasets from the database (they are put there by
python backend/manage.py sync_reference):
- NVD CVE dataset
- MITRE ATT&CK
- CISA KEV
- Historical attacks
"""

from engine import datastore


# ============================================================
# LOAD NVD CVE DATASET (the "recent" feed)
# ============================================================

def load_cve_dataset():

    cves = []

    try:

        for item in datastore.nvd_vulnerabilities(recent_only=True):

            cve = item["cve"]

            descriptions = cve.get("descriptions", [])

            severity = "UNKNOWN"

            try:

                severity = cve["metrics"][
                    "cvssMetricV31"
                ][0]["cvssData"]["baseSeverity"]

            except (KeyError, IndexError, TypeError):
                pass

            cves.append({

                "cve_id": cve.get("id"),

                "severity": severity or "UNKNOWN",

                "description": (
                    descriptions[0].get("value", "") if descriptions else ""
                )
            })

    except Exception as e:

        print(f"[Dataset Error] NVD dataset -> {e}")

    return cves


# ============================================================
# LOAD MITRE ATT&CK DATASET
# ============================================================

def load_mitre_dataset():

    techniques = []

    try:

        for obj in datastore.mitre_objects():

            if obj.get("type") != "attack-pattern":
                continue

            technique_id = None

            for ref in obj.get("external_references", []):

                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")

            techniques.append({

                "technique_id": technique_id,

                "name": obj.get("name"),

                "description": obj.get("description", "")
            })

    except Exception as e:

        print(f"[Dataset Error] MITRE dataset -> {e}")

    return techniques


# ============================================================
# LOAD CISA KEV DATASET
# ============================================================

def load_kev_dataset():

    try:
        return datastore.kev_entries()

    except Exception as e:

        print(f"[Dataset Error] KEV dataset -> {e}")

        return []


# ============================================================
# LOAD HISTORICAL ATTACKS
# ============================================================

def load_historical_attacks():

    try:
        return datastore.historical_attacks()

    except Exception as e:

        print(f"[Dataset Error] Historical attacks -> {e}")

        return []
