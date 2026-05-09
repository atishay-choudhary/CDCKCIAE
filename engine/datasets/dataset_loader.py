"""
Dataset Loader Module

Responsible for:
- NVD CVE dataset loading
- MITRE ATT&CK loading
- CISA KEV loading
- Historical attack loading
"""

import json


# ============================================================
# LOAD NVD CVE DATASET
# ============================================================

def load_cve_dataset(

    path="datasets/cves/raw/nvdcve-2.0-recent.json"
):

    cves = []

    try:

        with open(path, "r", encoding="utf-8") as f:

            data = json.load(f)

        vulnerabilities = data.get(
            "vulnerabilities",
            []
        )

        for item in vulnerabilities:

            cve = item.get("cve", {})

            cve_id = cve.get("id")

            # ------------------------------------------------
            # DESCRIPTION
            # ------------------------------------------------

            descriptions = cve.get(
                "descriptions",
                []
            )

            description = ""

            if descriptions:

                description = descriptions[0].get(
                    "value",
                    ""
                )

            # ------------------------------------------------
            # SEVERITY
            # ------------------------------------------------

            severity = "UNKNOWN"

            metrics = cve.get(
                "metrics",
                {}
            )

            try:

                severity = metrics[
                    "cvssMetricV31"
                ][0]["cvssData"]["baseSeverity"]

            except:
                pass

            cves.append({

                "cve_id": cve_id,

                "severity": severity,

                "description": description
            })

    except Exception as e:

        print(f"[Dataset Error] NVD dataset -> {e}")

    return cves


# ============================================================
# LOAD MITRE ATT&CK DATASET
# ============================================================

def load_mitre_dataset(

    path="datasets/mitre/raw/enterprise-attack.json"
):

    techniques = []

    try:

        with open(path, "r", encoding="utf-8") as f:

            data = json.load(f)

        objects = data.get(
            "objects",
            []
        )

        for obj in objects:

            if obj.get("type") != "attack-pattern":
                continue

            external_refs = obj.get(
                "external_references",
                []
            )

            technique_id = None

            for ref in external_refs:

                if ref.get("source_name") == "mitre-attack":

                    technique_id = ref.get(
                        "external_id"
                    )

            techniques.append({

                "technique_id": technique_id,

                "name": obj.get("name"),

                "description": obj.get(
                    "description",
                    ""
                )
            })

    except Exception as e:

        print(f"[Dataset Error] MITRE dataset -> {e}")

    return techniques


# ============================================================
# LOAD CISA KEV DATASET
# ============================================================

def load_kev_dataset(

    path=(
        "datasets/cisa/raw/"
        "known_exploited_vulnerabilities.json"
    )
):

    kev_entries = []

    try:

        with open(path, "r", encoding="utf-8") as f:

            data = json.load(f)

        vulnerabilities = data.get(
            "vulnerabilities",
            []
        )

        for vuln in vulnerabilities:

            kev_entries.append({

                "cve_id": vuln.get("cveID"),

                "vendor": vuln.get("vendorProject"),

                "product": vuln.get("product"),

                "name": vuln.get("vulnerabilityName")
            })

    except Exception as e:

        print(f"[Dataset Error] KEV dataset -> {e}")

    return kev_entries


# ============================================================
# LOAD HISTORICAL ATTACKS
# ============================================================

def load_historical_attacks(

    path="datasets/historical/historical_attacks.json"
):

    try:

        with open(path, "r", encoding="utf-8") as f:

            return json.load(f)

    except Exception as e:

        print(
            f"[Dataset Error] "
            f"Historical attacks -> {e}"
        )

        return []