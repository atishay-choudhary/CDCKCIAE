"""
Pipeline-facing threat assessment (FR-3.2, FR-4.2).

The trained classifier is the default engine; the rule-based scorer
is kept as the documented baseline and as the fallback when no
trained model exists yet (NFR Reliability).
"""

from engine.intelligence.threat_scorer import calculate_run_threat_level
from engine.ml.classifier import predict


SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# FR-3.2 makes the trained model the default engine. It is trained on
# NVD / ATT&CK text and is not yet validated on dark-web text (on the
# mock corpus it rates plainly critical content MEDIUM), so it is
# reported alongside the rule-based level and drives threat_level only
# when this is True. Flip once the dark-web validation set exists.
ML_DRIVES_THREAT_LEVEL = False


def assess_threat(documents, results, correlations):
    """
    Returns:
    - threat_level          : overall level used downstream
    - threat_level_baseline : rule-based level, always computed
    - threat_level_ml       : trained-model level (None if unavailable)
    - method                : which engine produced threat_level
    - documents             : per-document severity / kill-chain stage
                              predictions with confidence (FR-3.4)

    Overall level = most severe document-level prediction.
    """

    baseline = calculate_run_threat_level(results, correlations)

    fallback = {
        "threat_level": baseline,
        "threat_level_baseline": baseline,
        "threat_level_ml": None,
        "method": "rule-based",
        "documents": []
    }

    if not documents:
        return fallback

    try:
        severities = predict("severity", documents)
        stages = predict("stage", documents)

    except FileNotFoundError:
        print(
            "[!] Trained models not found "
            "(python -m engine.ml.classifier --task severity / stage); "
            "using rule-based scorer."
        )
        return fallback

    per_document = [
        {
            "severity": severity,
            "severity_confidence": severity_confidence,
            "kill_chain_stage": stage,
            "kill_chain_confidence": stage_confidence
        }
        for (severity, severity_confidence), (stage, stage_confidence)
        in zip(severities, stages)
    ]

    ml_level = max(
        (d["severity"] for d in per_document),
        key=SEVERITY_ORDER.index
    )

    return {
        "threat_level": ml_level if ML_DRIVES_THREAT_LEVEL else baseline,
        "threat_level_baseline": baseline,
        "threat_level_ml": ml_level,
        "method": "ml" if ML_DRIVES_THREAT_LEVEL else "rule-based",
        "documents": per_document
    }
