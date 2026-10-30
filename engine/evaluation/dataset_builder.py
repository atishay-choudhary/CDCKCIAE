"""
Labelled evaluation dataset builder (FR-8.1).

Builds two independent, reproducible datasets from the public ground
truth already in datasets/:

- severity.csv  : CVE description  -> NVD CVSS severity (+ CISA KEV flag)
- killchain.csv : ATT&CK technique -> Cyber Kill Chain stage

Labels come from NVD / CISA / MITRE, never from the rule-based scorer,
so the baseline comparison (FR-8.4) is on independent ground truth.
Train/test splits are fixed here so every model is scored on the
same held-out rows.

Run from the project root:
    python -m engine.evaluation.dataset_builder
"""

import csv
import gc
import json
import os
import re
from collections import Counter

from sklearn.model_selection import train_test_split

from engine.datasets.dataset_loader import load_kev_dataset


OUTPUT_DIR = "datasets/labelled"

NVD_FILES = [
    "datasets/cves/raw/nvdcve-2.0-2024.json",
    "datasets/cves/raw/nvdcve-2.0-2025.json",
    "datasets/cves/raw/nvdcve-2.0-modified.json",
    "datasets/cves/raw/nvdcve-2.0-recent.json",
]

MITRE_FILE = "datasets/mitre/raw/enterprise-attack.json"

SEED = 42
TEST_SIZE = 0.2

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command and Control",
    "Actions on Objectives",
]

# ATT&CK tactic -> Lockheed Martin Cyber Kill Chain stage.
# This table is a documented judgment call (the two models are not
# 1:1) and is the main labelling assumption: review before reporting.
TACTIC_TO_STAGE = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Weaponization",
    "initial-access": "Delivery",
    "execution": "Exploitation",
    "credential-access": "Exploitation",
    "privilege-escalation": "Exploitation",
    "persistence": "Installation",
    "stealth": "Installation",
    "defense-impairment": "Installation",
    "command-and-control": "Command and Control",
    "discovery": "Actions on Objectives",
    "lateral-movement": "Actions on Objectives",
    "collection": "Actions on Objectives",
    "exfiltration": "Actions on Objectives",
    "impact": "Actions on Objectives",
}

# VulDB-style sentence ("It has been classified as critical.") leaks a
# severity word that rarely matches the CVSS label; remove it.
_LEAK = re.compile(
    r"[^.]*\bclassified as (?:critical|high|medium|low)\b[^.]*\.\s*",
    re.IGNORECASE
)
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")


def _clean(text):

    text = _CITATION.sub("", text)
    text = _MD_LINK.sub(r"\1", text)

    return " ".join(text.split())


def _severity(metrics):

    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):

        if metrics.get(key):

            value = metrics[key][0]["cvssData"].get("baseSeverity")

            if value in SEVERITIES:
                return value

    return None


def _split(rows, label_key):

    labels = [row[label_key] for row in rows]

    train_idx, test_idx = train_test_split(
        range(len(rows)),
        test_size=TEST_SIZE,
        stratify=labels,
        random_state=SEED
    )

    test = set(test_idx)

    for i, row in enumerate(rows):
        row["split"] = "test" if i in test else "train"


def _write(rows, name, columns):

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    path = os.path.join(OUTPUT_DIR, name)

    with open(path, "w", encoding="utf-8", newline="") as f:

        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    return path


def build_severity_dataset():

    kev_ids = {
        entry["cve_id"] for entry in load_kev_dataset()
    }

    records = {}

    # Later files hold fresher records and overwrite earlier ones.
    for path in NVD_FILES:

        with open(path, "r", encoding="utf-8") as f:
            vulnerabilities = json.load(f)["vulnerabilities"]

        for item in vulnerabilities:

            cve = item["cve"]

            if cve.get("vulnStatus") == "Rejected":
                continue

            text = next(
                (
                    d["value"] for d in cve.get("descriptions", [])
                    if d.get("lang") == "en"
                ),
                ""
            )

            text = _clean(_LEAK.sub("", text))

            severity = _severity(cve.get("metrics", {}))

            if len(text) < 30 or severity is None:
                continue

            records[cve["id"]] = {
                "id": cve["id"],
                "text": text,
                "severity": severity,
                "exploited": int(cve["id"] in kev_ids)
            }

        del vulnerabilities
        gc.collect()

    rows = sorted(records.values(), key=lambda r: r["id"])

    _split(rows, "severity")

    return rows


def build_killchain_dataset():

    with open(MITRE_FILE, "r", encoding="utf-8") as f:
        objects = json.load(f)["objects"]

    rows = []
    dropped = 0

    for obj in objects:

        if (
            obj.get("type") != "attack-pattern"
            or obj.get("revoked")
            or obj.get("x_mitre_deprecated")
        ):
            continue

        tactics = sorted({
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p["kill_chain_name"] == "mitre-attack"
        })

        stages = {TACTIC_TO_STAGE[t] for t in tactics if t in TACTIC_TO_STAGE}

        # Keep only techniques whose tactics all map to one stage.
        if len(stages) != 1:
            dropped += 1
            continue

        technique_id = next(
            ref["external_id"]
            for ref in obj["external_references"]
            if ref.get("source_name") == "mitre-attack"
        )

        rows.append({
            "id": technique_id,
            "text": _clean(f"{obj['name']}. {obj.get('description', '')}"),
            "tactic": "|".join(tactics),
            "stage": stages.pop()
        })

    rows.sort(key=lambda r: r["id"])

    _split(rows, "stage")

    return rows, dropped


def main():

    severity_rows = build_severity_dataset()

    path = _write(
        severity_rows,
        "severity.csv",
        ["id", "text", "severity", "exploited", "split"]
    )

    print(f"[+] {path}: {len(severity_rows)} rows")
    print(f"    severity : {dict(Counter(r['severity'] for r in severity_rows))}")
    print(f"    exploited: {sum(r['exploited'] for r in severity_rows)}")

    killchain_rows, dropped = build_killchain_dataset()

    path = _write(
        killchain_rows,
        "killchain.csv",
        ["id", "text", "tactic", "stage", "split"]
    )

    print(f"[+] {path}: {len(killchain_rows)} rows "
          f"({dropped} multi-stage techniques excluded)")

    counts = Counter(r["stage"] for r in killchain_rows)

    for stage in KILL_CHAIN_STAGES:
        print(f"    {stage:<22}: {counts[stage]}")


if __name__ == "__main__":
    main()