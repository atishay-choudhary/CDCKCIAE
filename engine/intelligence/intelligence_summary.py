"""
Intelligence summarization module.

Responsible for:
- executive summaries
- NLP grouping
- MITRE summarization
- key findings generation
"""


# ============================================================
# GENERATE EXECUTIVE FINDINGS
# ============================================================

def summarize_findings(results):

    """
    Generates high-level intelligence findings.
    """

    findings = []

    keyword_map = {

        "access": (
            "Potential unauthorized access "
            "indicators detected."
        ),

        "exploit": (
            "Exploit-related activity "
            "or vulnerability targeting observed."
        ),

        "movement": (
            "Indicators suggest possible "
            "internal movement or escalation activity."
        ),

        "leak": (
            "Potential structured data leakage "
            "or archival exposure indicators identified."
        ),

        "sale": (
            "Marketplace or monetization-related "
            "threat activity detected."
        )
    }

    seen = set()

    for item in results:

        if item["type"] != "keyword":
            continue

        subtype = item["subtype"]

        if subtype in keyword_map:

            finding = keyword_map[subtype]

            if finding not in seen:

                findings.append(finding)

                seen.add(finding)

    return findings


# ============================================================
# GROUP NLP THREAT CATEGORIES
# ============================================================

def group_nlp_categories(correlations):

    """
    Groups NLP intelligence findings.
    """

    grouped = {}

    for item in correlations:

        if item["type"] != "nlp_keyword":
            continue

        category = item["category"]

        term = item["term"]

        frequency = item["frequency"]

        if category not in grouped:

            grouped[category] = []

        grouped[category].append({

            "term": term,

            "frequency": frequency
        })

    return grouped


# ============================================================
# SUMMARIZE MITRE TECHNIQUES
# ============================================================

def compact_mitre_output(

    mitre_dataset,

    limit=5
):

    """
    Returns compact MITRE mapping summary.
    """

    summarized = []

    seen = set()

    for technique in mitre_dataset:

        technique_id = technique.get(
            "technique_id"
        )

        name = technique.get(
            "name"
        )

        if not technique_id or not name:
            continue

        key = (

            technique_id,

            name
        )

        if key in seen:
            continue

        seen.add(key)

        summarized.append({

            "id": technique_id,

            "name": name
        })

        if len(summarized) >= limit:
            break

    return summarized


# ============================================================
# BUILD EXECUTIVE THREAT SUMMARY
# ============================================================

def build_executive_summary(

    threat_level,

    kill_chain
):

    """
    Builds executive CTI summary.
    """

    summary = []

    summary.append(

        f"Threat Level Assessed: "
        f"{threat_level}"
    )

    if kill_chain:

        summary.append(

            "Observed attack progression includes: "
            + " → ".join(kill_chain)
        )

    # --------------------------------------------------------
    # HIGH RISK SUMMARY
    # --------------------------------------------------------

    if threat_level == "CRITICAL":

        summary.append(

            "Threat posture indicates a potentially "
            "active multi-stage intrusion scenario."
        )

    elif threat_level == "HIGH":

        summary.append(

            "Threat indicators suggest elevated "
            "cyber risk activity."
        )

    elif threat_level == "MEDIUM":

        summary.append(

            "Moderate threat activity indicators "
            "were identified."
        )

    else:

        summary.append(

            "Current observed activity appears "
            "limited in severity."
        )

    return summary