"""
Kill chain mapping engine.
"""


def map_kill_chain(

    results,

    correlations=None
):

    """
    Maps extracted signals
    to attack stages.
    """

    if correlations is None:
        correlations = []

    stages = set()

    # ========================================================
    # SIGNAL-BASED MAPPING
    # ========================================================

    for item in results:

        if item["type"] != "keyword":
            continue

        subtype = item["subtype"]

        if subtype == "access":

            stages.add("Initial Access")

        elif subtype == "exploit":

            stages.add("Execution")

        elif subtype == "movement":

            stages.add("Privilege Escalation")

        elif subtype == "leak":

            stages.add("Exfiltration")

        elif subtype == "sale":

            stages.add("Monetization")

    # ========================================================
    # INTELLIGENCE-ASSISTED MAPPING
    # ========================================================

    for correlation in correlations:

        # ----------------------------------------------------
        # Exploited Vulnerabilities
        # ----------------------------------------------------

        if correlation["type"] == "kev_correlation":

            stages.add("Weaponization")

            stages.add("Initial Access")

        # ----------------------------------------------------
        # Historical Attacks
        # ----------------------------------------------------

        elif correlation["type"] == "historical_attack":

            stages.add("Execution")

    return list(stages)