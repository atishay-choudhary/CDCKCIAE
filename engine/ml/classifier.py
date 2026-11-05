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
import io

import joblib
import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline

from engine import datastore


SEED = 42

# task -> label name (the data is the labelled_sample table)
TASKS = {
    "severity": "severity",
    "stage": "stage",
}

class XGBText(BaseEstimator, ClassifierMixin):
    """
    Gradient-boosted trees (FR-3.1) behind the scikit-learn interface.

    XGBoost needs integer class ids, so labels are encoded here and the
    original strings are exposed through classes_. xgboost is an optional
    dependency, imported only when the model is fitted.
    """

    def __init__(self, n_estimators=300, max_depth=6, learning_rate=0.2):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.learning_rate = learning_rate

    def fit(self, X, y):

        try:
            from xgboost import XGBClassifier
        except ImportError as error:
            raise ImportError(
                "the xgboost model needs the optional package: pip install xgboost"
            ) from error

        self.classes_, encoded = np.unique(np.asarray(y), return_inverse=True)

        self.model_ = XGBClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            learning_rate=self.learning_rate,
            tree_method="hist",
            n_jobs=-1,
            random_state=SEED,
        )
        self.model_.fit(X, encoded)

        return self

    def predict_proba(self, X):
        return self.model_.predict_proba(X)

    def predict(self, X):
        return self.classes_[self.predict_proba(X).argmax(axis=1)]


# FR-3.1: selectable classifier.
MODELS = {
    "logreg": lambda C=1.0: LogisticRegression(
        max_iter=1000,
        C=C,
        class_weight="balanced"
    ),
    "rf": lambda C=1.0: RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        n_jobs=-1,
        random_state=SEED
    ),
    # linear SVM, calibrated so predict() still returns probabilities
    "svm": lambda C=0.3: CalibratedClassifierCV(
        LinearSVC(C=C, class_weight="balanced"), cv=3
    ),
    # optional: needs `pip install xgboost` (C is not used)
    "xgboost": lambda C=None: XGBText(),
}

PARAMS_KEY = "tuned_params:"

_loaded = {}


def load_split(task):
    """
    Returns (X_train, y_train, X_test, y_test) from the labelled_sample
    table, using the fixed split written by the dataset builder.
    """

    return datastore.labelled_split(task)


def tuned_params(task):
    """{"model", "C", "max_features"} saved by the tuning run, or None."""

    return datastore.cache_get(PARAMS_KEY + task)


def build_model(model_name="logreg", C=None, max_features=50000):

    options = {} if C is None else {"C": C}

    return Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                ngram_range=(1, 2),
                min_df=2,
                max_features=max_features,
                sublinear_tf=True,
                stop_words="english"
            )
        ),
        ("clf", MODELS[model_name](**options))
    ])


def pipeline_for(task, model_name="logreg"):
    """An unfitted pipeline: the tuned configuration if one is saved."""

    best = tuned_params(task)

    if best:
        return build_model(best["model"], best["C"], best["max_features"])

    return build_model(model_name)


def train(task, model_name="logreg", save=True):
    """
    Fits on the training split and (FR-3.3) persists the pipeline.
    """

    X_train, y_train, _, _ = load_split(task)

    pipeline = pipeline_for(task, model_name)
    pipeline.fit(X_train, y_train)

    if save:
        buffer = io.BytesIO()
        joblib.dump(pipeline, buffer)
        datastore.save_model(task, model_name, buffer.getvalue(), {
            "train_rows": len(X_train)
        })
        _loaded.pop(task, None)

    return pipeline


def predict(task, texts):
    """
    Returns [(label, confidence), ...] (FR-3.4) using the
    persisted model.
    """

    if task not in _loaded:
        blob = datastore.load_model(task)

        if blob is None:
            raise FileNotFoundError(f"no trained {task} model in the database")

        _loaded[task] = joblib.load(io.BytesIO(blob))

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

    print(f"[+] Saved {args.task} model to the database")
