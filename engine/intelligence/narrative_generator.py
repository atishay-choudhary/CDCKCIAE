"""
Threat narrative generator.
"""


def generate_narrative(

    results,

    kill_chain,

    threat_level,

    correlations=None
):

    if correlations is None:
        correlations = []

    keywords = set()

    for item in results:

        if item["type"] == "keyword":

            keywords.add(
                item["subtype"]
            )

    observations = []

    # ========================================================
    # ACCESS ANALYSIS
    # ========================================================

    if "access" in keywords:

        observations.append(
            "Potential unauthorized access "
            "indicators detected."
        )

    # ========================================================
    # EXPLOIT ANALYSIS
    # ========================================================

    if "exploit" in keywords:

        observations.append(
            "Exploit-related discussions suggest "
            "possible vulnerability targeting activity."
        )

    # ========================================================
    # MOVEMENT ANALYSIS
    # ========================================================

    if "movement" in keywords:

        observations.append(
            "Signals indicate possible privilege "
            "escalation or internal movement attempts."
        )

    # ========================================================
    # LEAK ANALYSIS
    # ========================================================

    if "leak" in keywords:

        observations.append(
            "Potential data exposure or archived "
            "breach material detected."
        )

    # ========================================================
    # SALE ANALYSIS
    # ========================================================

    if "sale" in keywords:

        observations.append(
            "Threat actor monetization activity "
            "detected through marketplace indicators."
        )

    # ========================================================
    # CVE CORRELATION ANALYSIS
    # ========================================================

    for correlation in correlations:

        if correlation["type"] == "cve_correlation":

            observations.append(
                f"Detected vulnerability correlation "
                f"with {correlation['cve']} "
                f"({correlation['severity']})."
            )

        elif correlation["type"] == "kev_correlation":

            observations.append(
                "Detected Known Exploited "
                "Vulnerability (KEV) correlation, "
                "indicating elevated exploitation risk."
            )

        elif correlation["type"] == "historical_attack":

            observations.append(
                f"Observed indicators resemble "
                f"historical attack patterns associated "
                f"with {correlation['attack_name']}."
            )

    # ========================================================
    # FINAL NARRATIVE
    # ========================================================

    narrative = "\n".join(
        f"- {obs}" for obs in observations
    )

    return f"""

THREAT INTELLIGENCE ASSESSMENT
==============================

Threat Level: {threat_level}

Detected Kill Chain Stages:
{", ".join(kill_chain)}

Assessment Summary:
{narrative}

Overall Assessment:
The collected indicators suggest a potentially active
cyber threat scenario involving exploitation activity,
possible unauthorized access, and data exposure risks.
"""