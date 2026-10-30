"""
Trained threat classifier (O1: FR-3.1 - FR-3.4).

Replaces keyword-weighted heuristics with a classifier fitted on the
labelled datasets from engine.evaluation.dataset_builder.

Tasks:
- severity : text -> LOW / MEDIUM / HIGH / CRITICAL
- stage    : text -> one of the seven Cyber Kill Chain stages

Train from the project root:
    python -m engine.ml.classifier --task severity --model logreg
"""

import argparse
import csv
import os

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


DATA_DIR = "datasets/labelled"
MODEL_DIR = "models"

SEED = 42

# task -> (csv file, label column)
TASKS = {
    "severity": ("severity.csv", "severity"),
    "stage": ("killchain.csv", "stage"),
}

# FR-3.1: selectable classifier.
MODELS = {
    "logreg": lambda: LogisticRegression(
        max_iter=1000,
        class_weight="balanced"
    ),
    "rf": lambda: RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        n_jobs=-1,
        random_state=SEED
    ),
}

_loaded = {}


def load_split(task):
    """
    Returns (X_train, y_train, X_test, y_test) using the fixed
    split column written by the dataset builder.
    """

    filename, label = TASKS[task]

    with open(
        os.path.join(DATA_DIR, filename),
        "r",
        encoding="utf-8",
        newline=""
    ) as f:
        rows = list(csv.DictReader(f))

    train = [r for r in rows if r["split"] == "train"]
    test = [r for r in rows if r["split"] == "test"]

    return (
        [r["text"] for r in train],
        [r[label] for r in train],
        [r["text"] for r in test],
        [r[label] for r in test],
    )


def build_model(model_name="logreg"):

    return Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                ngram_range=(1, 2),
                min_df=2,
                max_features=50000,
                sublinear_tf=True,
                stop_words="english"
            )
        ),
        ("clf", MODELS[model_name]())
    ])


def model_path(task):

    return os.path.join(MODEL_DIR, f"{task}.joblib")


def train(task, model_name="logreg", save=True):
    """
    Fits on the training split and (FR-3.3) persists the pipeline.
    """

    X_train, y_train, _, _ = load_split(task)

    pipeline = build_model(model_name)
    pipeline.fit(X_train, y_train)

    if save:
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(pipeline, model_path(task))
        _loaded.pop(task, None)

    return pipeline


def predict(task, texts):
    """
    Returns [(label, confidence), ...] (FR-3.4) using the
    persisted model.
    """

    if task not in _loaded:
        _loaded[task] = joblib.load(model_path(task))

    pipeline = _loaded[task]

    probabilities = pipeline.predict_proba(texts)
    classes = pipeline.classes_

    return [
        (str(classes[row.argmax()]), float(row.max()))
        for row in probabilities
    ]


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--task", choices=TASKS, required=True)
    parser.add_argument("--model", choices=MODELS, default="logreg")
    args = parser.parse_args()

    train(args.task, args.model)

    print(f"[+] Saved {model_path(args.task)}")