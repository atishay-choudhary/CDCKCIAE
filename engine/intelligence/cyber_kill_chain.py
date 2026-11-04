"""
Seven-stage Cyber Kill Chain mapping (FR-4.1, FR-4.2).

The pipeline's rule-based mapper produces ATT&CK-style stage names
(Initial Access, Exfiltration, ...). This module expresses that result
in the seven Lockheed Martin stages, using the same documented
tactic-to-stage table the classifier was trained on, and attaches the
trained stage classifier's output as a second signal:

- method "rule"    : stage found by the rule-based mapper only
- method "rule+ml" : rules and the classifier agree; confidence is the
                     classifier's probability for that stage
- method "ml"      : classifier only (only if ML_ADDS_STAGES is True)

The classifier is trained on ATT&CK text and not yet validated on
dark-web text, so by default it corroborates rule-found stages and
lists any other stage it predicts under "ml_only" instead of adding it
to the chain. Flip ML_ADDS_STAGES once the dark-web validation set
shows it is reliable (same policy as ML_DRIVES_THREAT_LEVEL).
"""

from engine.evaluation.dataset_builder import (
    KILL_CHAIN_STAGES,
    TACTIC_TO_STAGE
)


ML_ADDS_STAGES = False

# Names the rule-based mapper uses that are not in the ATT&CK table.
EXTRA_STAGES = {
    "defense-evasion": "Installation",
    "monetization": "Actions on Objectives",
    "weaponization": "Weaponization"
}


def _to_stage(pipeline_stage):

    key = pipeline_stage.strip().lower().replace(" ", "-")

    return TACTIC_TO_STAGE.get(key) or EXTRA_STAGES.get(key)


def map_cyber_kill_chain(kill_chain, threat_assessment=None):
    """
    Returns:
    - stages          : [{stage, method, confidence, evidence}] in
                        canonical kill-chain order
    - ml_only         : [{stage, confidence, documents}] stages the
                        classifier predicted that are not in the chain
    - unmapped        : pipeline stages with no kill-chain equivalent
    - ml_adds_stages  : the policy flag in effect
    """

    evidence, unmapped = {}, []

    for pipeline_stage in kill_chain:

        stage = _to_stage(pipeline_stage)

        if stage:
            evidence.setdefault(stage, []).append(pipeline_stage)

        else:
            unmapped.append(pipeline_stage)

    ml = {}

    for document in (threat_assessment or {}).get("documents", []):

        entry = ml.setdefault(
            document["kill_chain_stage"],
            {"confidence": 0.0, "documents": 0}
        )

        entry["confidence"] = max(
            entry["confidence"], document["kill_chain_confidence"]
        )

        entry["documents"] += 1

    stages = []

    for name in KILL_CHAIN_STAGES:

        by_rules = name in evidence

        by_ml = name in ml

        if not (by_rules or (by_ml and ML_ADDS_STAGES)):
            continue

        stages.append({
            "stage": name,
            "method": (
                "rule+ml" if by_rules and by_ml
                else "rule" if by_rules else "ml"
            ),
            "confidence": round(ml[name]["confidence"], 3) if by_ml else None,
            "evidence": sorted(evidence.get(name, []))
        })

    chained = {s["stage"] for s in stages}

    return {
        "stages": stages,
        "ml_only": [
            {
                "stage": name,
                "confidence": round(ml[name]["confidence"], 3),
                "documents": ml[name]["documents"]
            }
            for name in KILL_CHAIN_STAGES
            if name in ml and name not in chained
        ],
        "unmapped": unmapped,
        "ml_adds_stages": ML_ADDS_STAGES
    }


def print_cyber_kill_chain(result):

    if not result["stages"]:
        print("\nNo kill-chain stages observed.")

    for item in result["stages"]:

        confidence = (
            f"{item['confidence']:.2f}"
            if item["confidence"] is not None else "n/a"
        )

        print("\n----------------------------------------")

        print(f"Stage      : {item['stage']}")

        print(f"Method     : {item['method']} (ML confidence {confidence})")

        print(f"Evidence   : {', '.join(item['evidence']) or 'classifier'}")

    if result["ml_only"]:

        print("\nClassifier-only stages (not in chain, unvalidated on "
              "dark-web text):")

        for item in result["ml_only"]:

            print(
                f"  {item['stage']:<22} confidence {item['confidence']:.2f} "
                f"({item['documents']} document"
                f"{'s' if item['documents'] != 1 else ''})"
            )

    if result["unmapped"]:

        print(f"\nUnmapped pipeline stages: {', '.join(result['unmapped'])}")
