"""
Hyper-parameter search for the severity / stage classifiers (FR-3.1, O1).

Candidates are compared by stratified cross-validation on the TRAINING
split only; the held-out split is scored once, for the winner. The winner
is saved (store_cache) so training and evaluation use it from then on,
and the full trial table goes to stored_report "tuning".

Run from the project root:
    python -m engine.evaluation.tuning            # search and save
    python -m engine.evaluation.tuning --clear    # back to the defaults
"""

import argparse
import itertools
import random

from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import cross_val_score

from engine import datastore
from engine.ml.classifier import (
    PARAMS_KEY,
    SEED,
    TASKS,
    build_model,
    load_split,
    train
)


GRID = {
    "logreg": [1.0, 4.0, 10.0],
    "svm": [0.1, 0.3, 1.0],
}
FEATURES = [50000, 100000]

SEARCH_ROWS = 20000      # rows used for the search; the winner is refit on all
FOLDS = 3


def _subsample(X, y):

    if len(X) <= SEARCH_ROWS:
        return X, y

    chosen = random.Random(SEED).sample(range(len(X)), SEARCH_ROWS)

    return [X[i] for i in chosen], [y[i] for i in chosen]


def search(task):

    X_train, y_train, X_test, y_test = load_split(task)

    X, y = _subsample(X_train, y_train)

    trials = []

    for model, C, features in (
        (m, c, f)
        for m, cs in GRID.items() for c in cs for f in FEATURES
    ):

        scores = cross_val_score(
            build_model(model, C, features), X, y,
            cv=FOLDS, scoring="f1_macro"
        )

        trials.append({
            "model": model, "C": C, "max_features": features,
            "cv_macro_f1": round(float(scores.mean()), 4),
            "cv_std": round(float(scores.std()), 4)
        })

        print(f"  {task:<8} {model:<7} C={C:<5} features={features:<7} "
              f"CV macro-F1 {scores.mean():.3f}")

    best = max(trials, key=lambda t: t["cv_macro_f1"])

    params = {k: best[k] for k in ("model", "C", "max_features")}

    datastore.cache_set(PARAMS_KEY + task, params)

    model = train(task, params["model"])          # uses the saved params

    predicted = model.predict(X_test)

    return {
        "best": params,
        "trials": trials,
        "held_out": {
            "rows": len(y_test),
            "accuracy": round(accuracy_score(y_test, predicted), 4),
            "macro_f1": round(
                f1_score(y_test, predicted, average="macro"), 4
            )
        }
    }


def clear():

    for task in TASKS:
        datastore.cache_set(PARAMS_KEY + task, {})

    print("[+] Tuned parameters cleared; defaults will be used.")


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--clear", action="store_true")
    args = parser.parse_args()

    if args.clear:
        clear()
        return

    report = {}

    for task in TASKS:

        print(f"\n[{task}]")

        report[task] = search(task)

        h = report[task]["held_out"]

        print(f"  best {report[task]['best']} -> held-out "
              f"accuracy {h['accuracy']:.3f}, macro-F1 {h['macro_f1']:.3f}")

    datastore.save_report("tuning", report)

    print("\n[+] Trials stored in the database (stored_report: tuning). "
          "Run the evaluation to refresh the comparison.")


if __name__ == "__main__":
    main()
