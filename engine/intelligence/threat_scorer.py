"""
Threat severity scoring engine.
"""


def calculate_threat_score(

    results,

    correlations=None
):

    """
    Calculates overall threat level.
    """

    if correlations is None:
        correlations = []

    score = 0

    # ========================================================
    # SIGNAL SCORING
    # ========================================================

    for item in results:

        # ----------------------------------------------------
        # Keyword Intelligence
        # ----------------------------------------------------

        if item["type"] == "keyword":

            subtype = item["subtype"]

            if subtype == "access":
                score += 2

            elif subtype == "exploit":
                score += 4

            elif subtype == "movement":
                score += 5

            elif subtype == "leak":
                score += 6

            elif subtype == "sale":
                score += 4

        # ----------------------------------------------------
        # CVE Detection
        # ----------------------------------------------------

        elif item["type"] == "cve":

            score += 5

        # ----------------------------------------------------
        # IP Indicators
        # ----------------------------------------------------

        elif item["type"] == "ipv4":

            score += 2

    # ========================================================
    # CORRELATION SCORING
    # ========================================================

    for correlation in correlations:

        # ----------------------------------------------------
        # KEV Correlation
        # ----------------------------------------------------

        if correlation["type"] == "kev_correlation":

            score += 10

        # ----------------------------------------------------
        # Historical Attack Correlation
        # ----------------------------------------------------

        elif correlation["type"] == "historical_attack":

            score += 7

        # ----------------------------------------------------
        # Critical CVE Correlation
        # ----------------------------------------------------

        elif correlation["type"] == "cve_correlation":

            severity = correlation.get(
                "severity",
                "UNKNOWN"
            )

            if severity == "CRITICAL":
                score += 10

            elif severity == "HIGH":
                score += 7

            elif severity == "MEDIUM":
                score += 4

    # ========================================================
    # FINAL SEVERITY MAPPING
    # ========================================================

    if score >= 35:
        return "CRITICAL"

    elif score >= 22:
        return "HIGH"

    elif score >= 10:
        return "MEDIUM"

    return "LOW"