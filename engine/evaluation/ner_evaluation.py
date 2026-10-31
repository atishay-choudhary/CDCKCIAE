"""
Regex-vs-NER comparison on an annotated sample (FR-2.3, O2/O6).

Both extractors, and their merge (FR-2.4), are scored on snippets that
you annotate by hand. Two steps:

1. export : crawled snippets -> datasets/annotation/entities_to_label.csv
2. score  : your labelled copy -> precision / recall / F1 per type

Workflow (from the project root):
    python -m engine.evaluation.ner_evaluation export
    # copy entities_to_label.csv -> entities_labelled.csv, then in each
    # row list every entity of each type found in the text, separated
    # by |  (leave a cell empty if there is none)
    python -m engine.evaluation.ner_evaluation score

Annotation guide:
    emails, ipv4, cves, domains : as written in the text
    organizations  : companies / agencies / institutions
    locations      : countries, cities, regions
    products       : software / systems / services
    threat_actors  : hacker groups and handles
    malware_tools  : malware families and attack tools
Matching is case-insensitive on the exact string.
"""

import argparse
import csv
import json
import os
import random

from engine.evaluation.corpus import CORPUS_PATH
from engine.evaluation.darkweb_validation import _snippets
from engine.nlp.entity_extractor import extract_entities
from engine.nlp.entity_merge import merge_entities
from engine.nlp.ner_extractor import extract_named_entities


TO_LABEL_PATH = "datasets/annotation/entities_to_label.csv"
LABELLED_PATH = "datasets/annotation/entities_labelled.csv"
REPORT_PATH = "outputs/ner_evaluation.json"

TYPES = [
    "emails", "ipv4", "cves", "domains",
    "organizations", "locations", "products",
    "threat_actors", "malware_tools",
]

SAMPLE_SIZE = 100
SEED = 42


def export():

    snippets = {}

    with open(CORPUS_PATH, "r", encoding="utf-8") as f:

        for line in f:

            doc = json.loads(line)

            for snippet in _snippets(doc["text"]):
                snippets.setdefault(snippet, {
                    "source": doc["url"],
                    "source_type": doc["source_type"],
                    "text": snippet
                })

    rows = list(snippets.values())

    random.Random(SEED).shuffle(rows)

    rows = rows[:SAMPLE_SIZE]

    for i, row in enumerate(rows, 1):
        row["id"] = f"ent-{i:03d}"
        row.update({t: "" for t in TYPES})

    os.makedirs(os.path.dirname(TO_LABEL_PATH), exist_ok=True)

    with open(TO_LABEL_PATH, "w", encoding="utf-8", newline="") as f:

        writer = csv.DictWriter(
            f, fieldnames=["id", "source", "source_type", "text"] + TYPES
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] {len(rows)} snippets -> {TO_LABEL_PATH}")
    print(f"    Copy it to {LABELLED_PATH}, fill the entity columns "
          f"(separate values with |), then run: score")


def _cell(value):

    return {v.strip().lower() for v in (value or "").split("|") if v.strip()}


def _pairs(entities):

    return {
        (kind, value.lower())
        for kind, values in entities.items() for value in values
    }


def _prf(tp, fp, fn):

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )

    return round(precision, 3), round(recall, 3), round(f1, 3)


def score():

    with open(LABELLED_PATH, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    systems = {"regex": {}, "ner": {}, "merged": {}}

    counts = {
        name: {t: [0, 0, 0] for t in TYPES + ["ALL"]} for name in systems
    }

    gold_support = {t: 0 for t in TYPES + ["ALL"]}

    for row in rows:

        gold = {(t, v) for t in TYPES for v in _cell(row.get(t))}

        regex = extract_entities(row["text"])
        ner = extract_named_entities(row["text"])

        predicted = {
            "regex": _pairs(regex),
            "ner": _pairs(ner),
            "merged": _pairs(merge_entities(regex, ner)["entities"]),
        }

        for kind in TYPES + ["ALL"]:

            g = gold if kind == "ALL" else {p for p in gold if p[0] == kind}

            gold_support[kind] += len(g)

            for name, pred in predicted.items():

                p = pred if kind == "ALL" else {
                    x for x in pred if x[0] == kind
                }

                counts[name][kind][0] += len(p & g)
                counts[name][kind][1] += len(p - g)
                counts[name][kind][2] += len(g - p)

    report = {
        "rows": len(rows),
        "support": gold_support,
        **{
            name: {
                kind: dict(zip(("precision", "recall", "f1"), _prf(*c)))
                for kind, c in per_type.items()
            }
            for name, per_type in counts.items()
        }
    }

    print(f"\n=== Regex vs NER ({len(rows)} annotated snippets) ===")
    print(f"{'type':<15}{'gold':>5}  {'regex':>16}{'ner':>16}{'merged':>16}")
    print(f"{'':<20}{'P/R/F1':>18}{'P/R/F1':>16}{'P/R/F1':>16}")

    for kind in TYPES + ["ALL"]:

        if not gold_support[kind]:
            continue

        cells = "".join(
            f"{report[n][kind]['precision']:>8.2f}/"
            f"{report[n][kind]['recall']:.2f}/"
            f"{report[n][kind]['f1']:.2f}"
            for n in systems
        )

        print(f"{kind:<15}{gold_support[kind]:>5}  {cells}")

    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n[+] {REPORT_PATH}")


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("step", choices=["export", "score"])
    args = parser.parse_args()

    export() if args.step == "export" else score()