"""
Threat narrative generator.
"""


def generate_narrative(results, kill_chain, threat_level):

    keywords = set()

    for item in results:

        if item["type"] == "keyword":
            keywords.add(item["subtype"])

    observations = []

    # --------------------------------------------------------
    # Access Analysis
    # --------------------------------------------------------

    if "access" in keywords:

        observations.append(
            "Potential unauthorized access indicators detected."
        )

    # --------------------------------------------------------
    # Exploit Analysis
    # --------------------------------------------------------

    if "exploit" in keywords:

        observations.append(
            "Exploit-related discussions suggest possible "
            "vulnerability targeting activity."
        )

    # --------------------------------------------------------
    # Movement Analysis
    # --------------------------------------------------------

    if "movement" in keywords:

        observations.append(
            "Signals indicate possible privilege escalation "
            "or internal movement attempts."
        )

    # --------------------------------------------------------
    # Leak Analysis
    # --------------------------------------------------------

    if "leak" in keywords:

        observations.append(
            "Potential data exposure or archived breach "
            "material detected."
        )

    # --------------------------------------------------------
    # Sale Analysis
    # --------------------------------------------------------

    if "sale" in keywords:

        observations.append(
            "Threat actor monetization activity detected "
            "through marketplace-related indicators."
        )

    # --------------------------------------------------------
    # Final Narrative
    # --------------------------------------------------------

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