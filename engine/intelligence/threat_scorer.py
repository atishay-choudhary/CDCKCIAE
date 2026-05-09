"""
Threat severity scoring engine.
"""


def calculate_threat_score(results):

    """
    Calculates overall threat level.
    """

    score = 0

    for item in results:

        if item["type"] != "keyword":
            continue

        subtype = item["subtype"]

        if subtype == "access":
            score += 2

        elif subtype == "exploit":
            score += 3

        elif subtype == "movement":
            score += 4

        elif subtype == "leak":
            score += 5

        elif subtype == "sale":
            score += 3

    # Severity mapping
    if score >= 12:
        return "CRITICAL"

    elif score >= 8:
        return "HIGH"

    elif score >= 4:
        return "MEDIUM"

    return "LOW"