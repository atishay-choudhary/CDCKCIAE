"""
Kill chain mapping engine.
"""


def map_kill_chain(results):

    """
    Maps extracted signals
    to attack stages.
    """

    stages = set()

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

    return list(stages)