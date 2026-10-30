"""
Evaluation harness and baseline comparison (FR-8.2, FR-8.4).

Scores the trained classifier and the original rule-based modules
on the same held-out rows, with precision / recall / F1 and a
confusion matrix per class.

Baseline = the unchanged minor-project code:
- severity : extract_basic -> calculate_threat_score (no correlations;
             CVE-dataset severity would leak the label)
- stage    : extract_basic -> map_kill_chain, mapped to the seven stages

Run from the project root:
    python -m engine.evaluation.evaluate --model logreg
"""

import argparse
import json
import os
from collections import Counter, defaultdict

from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support
)
from sklearn.model_selection import cross_val_score

from engine.evaluation.dataset_builder import KILL_CHAIN_STAGES
from engine.extractors.regex_basics import extract_basic
from engine.intelligence.killchain_mapper import map_kill_chain
from engine.intelligence.threat_scorer import calculate_threat_score
from engine.ml.classifier import (
    MODELS,
    TASKS,
    build_model,
    load_split,
    train
)


REPORT_PATH = "outputs/evaluation_report.json"

SEVERITY_LABELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

NO_PREDICTION = "NONE"

TASK_LABELS = {
    "severity": SEVERITY_LABELS,
    "stage": KILL_CHAIN_STAGES,
}

# Cross-validate where the held-out set is too small to be stable.
CV_TASKS = {"stage"}

# Rule-based mapper stage names -> Cyber Kill Chain stages
# (consistent with TACTIC_TO_STAGE in dataset_builder).
BASELINE_STAGE_MAP = {
    "Weaponization": "Weaponization",
    "Initial Access": "Delivery",
    "Execution": "Exploitation",
    "Privilege Escalation": "Exploitation",
    "Exfiltration": "Actions on Objectives",
    "Monetization": "Actions on Objectives",
}


def _signals(text):
    """
    Builds the `results` list exactly as engine.pipeline does.
    """

    extracted = extract_basic(text)

    results = []

    for subtype, values in extracted["keywords"].items():
        for value in values:
            results.append({
                "type": "keyword",
                "subtype": subtype,
                "value": value
            })

    for cve in extracted["cves"]:
        results.append({"type": "cve", "value": cve})

    for ip in extracted["ipv4"]:
        results.append({"type": "ipv4", "value": ip})

    return results


def baseline_severity(text):

    return calculate_threat_score(_signals(text))


def baseline_stage(text):
    """
    The mapper returns an unordered set of stages; the earliest
    kill-chain stage is taken as the single prediction.
    """

    mapped = {
        BASELINE_STAGE_MAP[s]
        for s in map_kill_chain(_signals(text))
        if s in BASELINE_STAGE_MAP
    }

    for stage in KILL_CHAIN_STAGES:
        if stage in mapped:
            return stage

    return NO_PREDICTION


BASELINES = {
    "severity": baseline_severity,
    "stage": baseline_stage,
}


def _signature(text):
    """
    The set of rule-based signals present (keyword subtypes, CVE, IP).
    """

    return frozenset(s.get("subtype") or s["type"] for s in _signals(text))


def tuned_baseline(task):
    """
    Upper bound for the rule-based feature set: each signal
    combination is mapped to its majority label on the training
    split (replaces the hand-set thresholds / stage map).
    """

    X_train, y_train, _, _ = load_split(task)

    table = defaultdict(Counter)

    for text, label in zip(X_train, y_train):
        table[_signature(text)][label] += 1

    majority = {
        signature: counts.most_common(1)[0][0]
        for signature, counts in table.items()
    }

    fallback = Counter(y_train).most_common(1)[0][0]

    return lambda text: majority.get(_signature(text), fallback)


def score(y_true, y_pred, labels):

    precision, recall, f1, support = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=labels,
        zero_division=0
    )

    matrix_labels = labels + [NO_PREDICTION]

    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "macro_f1": f1_score(
            y_true,
            y_pred,
            labels=labels,
            average="macro",
            zero_division=0
        ),
        "per_class": {
            label: {
                "precision": float(precision[i]),
                "recall": float(recall[i]),
                "f1": float(f1[i]),
                "support": int(support[i])
            }
            for i, label in enumerate(labels)
        },
        "confusion_matrix": {
            "labels": matrix_labels,
            "rows_true_cols_predicted": confusion_matrix(
                y_true,
                y_pred,
                labels=matrix_labels
            ).tolist()
        }
    }


def evaluate_task(task, model_name):

    labels = TASK_LABELS[task]

    _, _, X_test, y_test = load_split(task)

    pipeline = train(task, model_name)

    model_pred = pipeline.predict(X_test)
    base_pred = [BASELINES[task](text) for text in X_test]

    tuned = tuned_baseline(task)
    tuned_pred = [tuned(text) for text in X_test]

    report = {
        "model": model_name,
        "test_rows": len(y_test),
        "classifier": score(y_test, list(model_pred), labels),
        "baseline": score(y_test, base_pred, labels),
        "baseline_tuned": score(y_test, tuned_pred, labels),
    }

    if task in CV_TASKS:

        X_train, y_train, _, _ = load_split(task)

        folds = cross_val_score(
            build_model(model_name),
            X_train + X_test,
            y_train + y_test,
            cv=5,
            scoring="f1_macro"
        )

        report["classifier_cv_macro_f1"] = {
            "mean": float(folds.mean()),
            "std": float(folds.std())
        }

    return report


def _print(task, report):

    print(f"\n=== {task} ({report['test_rows']} test rows, "
          f"model={report['model']}) ===")

    sides = ("baseline", "baseline_tuned", "classifier")

    print(f"{'':<24}" + "".join(f"{side:>17}" for side in sides))
    print(f"{'':<24}" + f"{'P/R/F1':>17}" * len(sides))

    for label in report["classifier"]["per_class"]:

        cells = ""

        for side in sides:
            m = report[side]["per_class"][label]
            cells += (
                f"{m['precision']:>7.2f}/{m['recall']:.2f}/{m['f1']:.2f}"
            )

        print(
            f"{label:<24}{cells}"
            f"   (n={report['classifier']['per_class'][label]['support']})"
        )

    for side in sides:
        print(
            f"{side:<15} accuracy={report[side]['accuracy']:.3f}  "
            f"macro-F1={report[side]['macro_f1']:.3f}"
        )

    if "classifier_cv_macro_f1" in report:
        cv = report["classifier_cv_macro_f1"]
        print(f"classifier 5-fold CV macro-F1 = "
              f"{cv['mean']:.3f} +/- {cv['std']:.3f}")


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--model", choices=MODELS, default="logreg")
    args = parser.parse_args()

    full = {}

    for task in TASKS:

        full[task] = evaluate_task(task, args.model)
        _print(task, full[task])

    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(full, f, indent=2)

    print(f"\n[+] Full report (incl. confusion matrices): {REPORT_PATH}")


if __name__ == "__main__":
    main()