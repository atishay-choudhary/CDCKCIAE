"""
Dark-web validation set (FR-8.1, O6).

Measures how the trained models and the rule-based baseline perform on
real dark-web text, which the NVD / ATT&CK-trained models have never
seen. Two steps:

1. export : crawled snippets -> datasets/annotation/darkweb_to_label.csv
2. score  : your labelled copy -> precision / recall / F1 report

Workflow (from the project root):
    python -m engine.evaluation.darkweb_validation export
    # copy darkweb_to_label.csv -> darkweb_labelled.csv, fill the
    # `severity` and `stage` columns by hand (both annotators, agree)
    python -m engine.evaluation.darkweb_validation score
"""

import argparse
import csv
import json
import os
import random
import re
import textwrap

from engine.evaluation.corpus import CORPUS_PATH
from engine.evaluation.evaluate import (
    BASELINES,
    TASK_LABELS,
    _print,
    score,
    tuned_baseline
)
from engine.ml.classifier import predict


TO_LABEL_PATH = "datasets/annotation/darkweb_to_label.csv"
LABELLED_PATH = "datasets/annotation/darkweb_labelled.csv"

SNIPPET_CHARS = 400
SAMPLE_SIZE = 150
SEED = 42

COLUMNS = ["id", "source_type", "source", "text", "severity", "stage"]


def _snippets(text):

    pieces = [
        piece
        for sentence in re.split(r"(?<=[.!?])\s+", text)
        for piece in textwrap.wrap(sentence, SNIPPET_CHARS)
    ]

    chunk = ""

    for piece in pieces:

        if chunk and len(chunk) + len(piece) > SNIPPET_CHARS:
            yield chunk
            chunk = piece

        else:
            chunk = f"{chunk} {piece}".strip()

    if len(chunk) >= 30:
        yield chunk


def export():

    snippets = {}

    with open(CORPUS_PATH, "r", encoding="utf-8") as f:

        for line in f:

            doc = json.loads(line)

            for snippet in _snippets(doc["text"]):

                snippets.setdefault(snippet, {
                    "source_type": doc["source_type"],
                    "source": doc["url"],
                    "text": snippet
                })

    rows = list(snippets.values())

    random.Random(SEED).shuffle(rows)

    rows = rows[:SAMPLE_SIZE]

    for i, row in enumerate(rows, 1):
        row.update({"id": f"dw-{i:03d}", "severity": "", "stage": ""})

    os.makedirs(os.path.dirname(TO_LABEL_PATH), exist_ok=True)

    with open(TO_LABEL_PATH, "w", encoding="utf-8", newline="") as f:

        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] {len(rows)} snippets -> {TO_LABEL_PATH}")
    print(f"    Copy it to {LABELLED_PATH} and fill:")
    print(f"      severity : {' / '.join(TASK_LABELS['severity'])}")
    print(f"      stage    : {' / '.join(TASK_LABELS['stage'])} "
          f"(leave blank if none applies)")


def run_score():

    with open(LABELLED_PATH, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    for task in ("severity", "stage"):

        labels = TASK_LABELS[task]

        for row in rows:
            value = row[task].strip()
            row[task] = value.upper() if task == "severity" else value

        invalid = {r[task] for r in rows if r[task] and r[task] not in labels}

        if invalid:
            print(f"[!] {task}: ignoring unrecognised labels {sorted(invalid)}")

        subset = [r for r in rows if r[task] in labels]

        if not subset:
            print(f"[!] {task}: no labelled rows, skipped")
            continue

        texts = [r["text"] for r in subset]
        truth = [r[task] for r in subset]

        tuned = tuned_baseline(task)

        _print(task, {
            "model": "saved",
            "test_rows": len(subset),
            "classifier": score(
                truth,
                [label for label, _ in predict(task, texts)],
                labels
            ),
            "baseline": score(
                truth,
                [BASELINES[task](t) for t in texts],
                labels
            ),
            "baseline_tuned": score(
                truth,
                [tuned(t) for t in texts],
                labels
            ),
        })


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("step", choices=["export", "score"])
    args = parser.parse_args()

    export() if args.step == "export" else run_score()