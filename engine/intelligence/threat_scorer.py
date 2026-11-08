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

# ============================================================
# RUN-LEVEL THREAT LEVEL
# ============================================================

# what one distinct kind of activity is worth, counted once however
# many times a page repeats it
CATEGORY_POINTS = {
    "access": 2,
    "exploit": 4,
    "movement": 5,
    "leak": 6,
    "sale": 4,
}


def calculate_run_threat_level(results, correlations=None):

    """
    Overall level of a whole collection run.

    calculate_threat_score adds points per signal, so any run with a few
    dozen keyword hits reaches CRITICAL. Here each kind of activity counts
    once, an unconfirmed CVE counts 1, and evidence from a single site
    cannot reach CRITICAL unless the KEV catalogue or an NVD severity
    backs it. The per-document score above is unchanged: it is the
    baseline the classifiers are evaluated against.
    """

    from engine.intelligence.fair_risk import _site

    correlations = correlations or []

    score = sum(
        CATEGORY_POINTS[c]
        for c in {
            r["subtype"] for r in results
            if r["type"] == "keyword" and r.get("subtype") in CATEGORY_POINTS
        }
    )


    score += min(2 * len({r["value"] for r in results if r["type"] == "ipv4"}), 6)

    confirmed = False

    for correlation in correlations:

        kind = correlation["type"]

        if kind == "kev_correlation":
            score += 10
            confirmed = True

        elif kind == "historical_attack":
            score += 7

        elif kind == "cve_correlation":

            points = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4}.get(
                correlation.get("severity", "UNKNOWN"), 0
            )

            score += points
            confirmed = confirmed or points >= 7

    unconfirmed = {
        r["value"].lower() for r in results if r["type"] == "cve"
    }

    score += min(len(unconfirmed), 3)

    sites = {_site(r.get("source")) for r in results if r.get("source")}

    if score >= 28 and (confirmed or len(sites) >= 3):
        return "CRITICAL"

    if score >= 22:
        return "HIGH"

    if score >= 10:
        return "MEDIUM"

    return "LOW"
