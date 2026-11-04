"""
Labelled evaluation dataset builder (FR-8.1).

Run from the project root:
    python -m engine.evaluation.dataset_builder
"""

import re
from collections import Counter

from sklearn.model_selection import train_test_split

from engine import datastore
from engine.datasets.dataset_loader import load_kev_dataset


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


def build_severity_dataset():

    kev_ids = {
        entry["cve_id"] for entry in load_kev_dataset()
    }

    records = {}

    for item in datastore.nvd_vulnerabilities():

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

    rows = sorted(records.values(), key=lambda r: r["id"])

    _split(rows, "severity")

    return rows


def build_killchain_dataset():

    objects = datastore.mitre_objects()

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

    datastore.save_labelled("severity", severity_rows)

    print(f"[+] severity: {len(severity_rows)} rows stored in the database")

    killchain_rows, dropped = build_killchain_dataset()

    datastore.save_labelled("stage", killchain_rows)

    print(f"[+] stage: {len(killchain_rows)} rows stored in the database")


if __name__ == "__main__":
    main()
