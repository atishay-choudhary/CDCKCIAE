"""
Dark-web validation set (FR-8.1, O6).

Measures how the trained models and the rule-based baseline perform on
real dark-web text, which the NVD / ATT&CK-trained models have never
seen. Two steps:

1. export : corpus_document snippets -> annotation_sample table
2. label  : record your labels in the table, one snippet at a time
3. score  : labelled snippets -> precision / recall / F1 report

Workflow (from the project root):
    python -m engine.evaluation.darkweb_validation export
    python -m engine.evaluation.darkweb_validation label dw-001 severity=HIGH stage=Delivery
    python -m engine.evaluation.darkweb_validation score
"""

import argparse
import random
import re
import textwrap

from engine import datastore
from engine.evaluation.evaluate import (
    BASELINES,
    TASK_LABELS,
    _print,
    score,
    tuned_baseline
)
from engine.ml.classifier import predict


TASK = "darkweb"

SNIPPET_CHARS = 400
SAMPLE_SIZE = 150
SEED = 42

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

    for doc in datastore.documents():

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
        row["id"] = f"dw-{i:03d}"

    datastore.annotation_replace(TASK, rows)

    print(f"[+] {len(rows)} snippets stored in the database (annotation_sample)")
    print("    Label each one: label <id> severity=... stage=...")
    print(f"      severity : {' / '.join(TASK_LABELS['severity'])}")
    print(f"      stage    : {' / '.join(TASK_LABELS['stage'])} "
          f"(leave blank if none applies)")


def label(sample_id, pairs):

    values = dict(p.split("=", 1) for p in pairs)

    datastore.annotation_label(TASK, sample_id, values)

    print(f"[+] {sample_id}: {values}")


def run_score():

    rows = datastore.annotation_rows(TASK)

    for task in ("severity", "stage"):

        labels = TASK_LABELS[task]

        for row in rows:
            value = str(row.get(task, "")).strip()
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
    parser.add_argument("step", choices=["export", "label", "score"])
    parser.add_argument("id", nargs="?")
    parser.add_argument("labels", nargs="*", help="severity=HIGH stage=Delivery")
    args = parser.parse_args()

    if args.step == "export":
        export()

    elif args.step == "label":
        label(args.id, args.labels)

    else:
        run_score()
