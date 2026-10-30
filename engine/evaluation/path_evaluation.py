"""
Attack-path accuracy evaluation (FR-8.3).

Compares the predicted most-likely path (O3) with the original
propagation engine's highest-probability path, on two ground truths:

1. held-out ATT&CK intrusion sets (transitions learned on the other
   groups only), entry = Initial Access
2. the historical incidents in datasets/historical (techniques ->
   stages), entry = the incident's earliest stage

Metrics (ATT&CK does not record temporal order, so order is not scored):
- stage-set precision / recall / F1 of the path's stages after the entry
  against the stages the real actor used. Favors long paths (an actor
  uses ~10 stages), so it penalises a likelihood-maximising path.
- plausibility (added after seeing the above, as the criterion matching
  what a "most likely" path optimises):
    path support = share of cases where the actor used EVERY stage
                   on the path
    edge support = mean share of path transitions A->B where the
                   actor used both A and B

Run from the project root:
    python -m engine.evaluation.path_evaluation
"""

import json
import math
import os
import random
from statistics import mean

from engine.graph.path_prediction import (
    STAGE_ORDER,
    build_graph,
    learn_transitions,
    load_attack_data,
    most_likely_paths
)
from engine.intelligence.propagation_engine import (
    calculate_probability,
    traverse_attack_paths
)


HISTORICAL_PATH = "datasets/historical/historical_attacks.json"
REPORT_PATH = "outputs/path_evaluation.json"

SEED = 42
TEST_FRACTION = 0.2


def baseline_path(entry):
    """
    Original engine: its highest-probability path (its probability
    grows with depth, so this is the deepest path).
    """

    return max(
        traverse_attack_paths(entry),
        key=lambda p: calculate_probability(len(p))
    )


def prf(path, entry, truth):

    predicted = set(path) - {entry}
    actual = truth - {entry}

    hits = len(predicted & actual)

    precision = hits / len(predicted) if predicted else 0.0
    recall = hits / len(actual)
    f1 = (
        2 * precision * recall / (precision + recall)
        if hits else 0.0
    )

    return precision, recall, f1


def support(path, truth):

    edges = list(zip(path, path[1:]))

    return (
        float(set(path) <= truth),
        sum(a in truth and b in truth for a, b in edges) / len(edges)
    )


def evaluate(cases, graph):
    """
    cases: [(entry, truth_stage_set), ...] with >= 1 stage after entry.
    """

    totals = {"baseline": [0.0] * 5, "model": [0.0] * 5}

    for entry, truth in cases:

        paths = {
            "baseline": baseline_path(entry),
            "model": most_likely_paths(graph, entry, 1)[0][0]
        }

        for name, path in paths.items():

            for i, value in enumerate(
                prf(path, entry, truth) + support(path, truth)
            ):
                totals[name][i] += value

    n = len(cases)

    return {
        "cases": n,
        **{
            name: {
                "precision": round(values[0] / n, 3),
                "recall": round(values[1] / n, 3),
                "f1": round(values[2] / n, 3),
                "path_support": round(values[3] / n, 3),
                "edge_support": round(values[4] / n, 3)
            }
            for name, values in totals.items()
        }
    }


def calibration(groups, folds=5):
    """
    Both systems state a probability per path. Compare it with how
    often held-out actors (k-fold, no leakage) used every stage of
    that path. Returns mean absolute error per system.
    """

    chunks = [groups[i::folds] for i in range(folds)]

    paths = traverse_attack_paths("Initial Access")

    errors = {"baseline": [], "model": []}

    for i, held_out in enumerate(chunks):

        graph = build_graph(learn_transitions([
            g for j, chunk in enumerate(chunks) if j != i for g in chunk
        ]))

        pool = [g for g in held_out if "Initial Access" in g]

        for path in paths:

            observed = sum(set(path) <= g for g in pool) / len(pool)

            predicted = {
                "baseline": calculate_probability(len(path)),
                "model": math.prod(
                    graph[a][b]["probability"]
                    for a, b in zip(path, path[1:])
                )
            }

            for name, value in predicted.items():
                errors[name].append(abs(value - observed))

    return {
        "paths": len(paths),
        **{name: round(mean(v), 3) for name, v in errors.items()}
    }


def group_cases(groups):

    return [
        ("Initial Access", stages)
        for stages in groups
        if "Initial Access" in stages and len(stages) > 1
    ]


def incident_cases(technique_stages):

    with open(HISTORICAL_PATH, "r", encoding="utf-8") as f:
        attacks = json.load(f)

    cases = []

    for attack in attacks:

        stages = set().union(*(
            technique_stages.get(t, set())
            for t in attack["techniques"]
        ))

        ordered = [s for s in STAGE_ORDER if s in stages]

        if len(ordered) > 1:
            cases.append((ordered[0], stages))

    return cases, len(attacks)


def _print(title, result):

    print(f"\n=== {title} ({result['cases']} cases) ===")
    print(
        f"{'':<12}{'precision':>10}{'recall':>9}{'F1':>8}"
        f"{'path supp.':>12}{'edge supp.':>12}"
    )

    for name in ("baseline", "model"):

        r = result[name]

        print(
            f"{name:<12}{r['precision']:>10.3f}"
            f"{r['recall']:>9.3f}{r['f1']:>8.3f}"
            f"{r['path_support']:>12.3f}{r['edge_support']:>12.3f}"
        )


def main():

    technique_stages, groups = load_attack_data()

    groups = groups[:]

    random.Random(SEED).shuffle(groups)

    split = int(len(groups) * (1 - TEST_FRACTION))

    train, test = groups[:split], groups[split:]

    train_graph = build_graph(learn_transitions(train))

    group_result = evaluate(group_cases(test), train_graph)

    # Incidents are a separate ground truth: use all groups for learning.
    full_graph = build_graph(learn_transitions(groups))

    cases, total = incident_cases(technique_stages)

    incident_result = evaluate(cases, full_graph)

    _print(
        f"Held-out ATT&CK groups (learned on {len(train)})",
        group_result
    )
    _print(
        f"Historical incidents ({total - len(cases)} of {total} "
        f"have < 2 mappable stages)",
        incident_result
    )

    calibration_result = calibration(groups)

    print(
        f"\n=== Probability calibration ({calibration_result['paths']} "
        f"paths from Initial Access, 5-fold) ==="
    )
    print("mean |stated probability - observed support| (lower is better)")
    print(f"baseline  {calibration_result['baseline']:.3f}")
    print(f"model     {calibration_result['model']:.3f}")

    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(
            {
                "held_out_groups": group_result,
                "incidents": incident_result,
                "calibration": calibration_result
            },
            f,
            indent=2
        )

    print(f"\n[+] {REPORT_PATH}")


if __name__ == "__main__":
    main()