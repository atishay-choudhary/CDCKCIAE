"""
Cross-Domain Impact Intelligence Engine.

Responsible for:
- business impact analysis
- operational consequence modeling
- compliance exposure assessment
- propagation path estimation
"""


# ============================================================
# BUILD CROSS-DOMAIN IMPACT ASSESSMENT
# ============================================================

def analyze_cross_domain_impact(

    results,
    kill_chain,
    threat_level,
    ioc_enrichment=None
):

    """
    Generates structured impact intelligence.
    """

    if ioc_enrichment is None:
        ioc_enrichment = []

    business_impact = []
    operational_impact = []
    compliance_impact = []
    affected_assets = []
    propagation_paths = []

    impact_score = 0

    # ========================================================
    # SIGNAL ANALYSIS
    # ========================================================

    for item in results:

        item_type = item.get("type")

        # ----------------------------------------------------
        # KEYWORD ANALYSIS
        # ----------------------------------------------------

        if item_type == "keyword":

            subtype = item.get("subtype")

            # ------------------------------------------------
            # ACCESS IMPACT
            # ------------------------------------------------

            if subtype == "access":

                business_impact.append(
                    "Potential unauthorized system access may impact business operations."
                )

                operational_impact.append(
                    "Unauthorized foothold may enable persistence within infrastructure."
                )

                propagation_paths.append(
                    "External Access → Internal Systems"
                )

                impact_score += 3

            # ------------------------------------------------
            # EXPLOIT IMPACT
            # ------------------------------------------------

            elif subtype == "exploit":

                business_impact.append(
                    "Exploit activity may expose vulnerable production services."
                )

                operational_impact.append(
                    "Remote code execution risk may impact service availability."
                )

                propagation_paths.append(
                    "Application Layer → Server Infrastructure"
                )

                impact_score += 5

            # ------------------------------------------------
            # MOVEMENT IMPACT
            # ------------------------------------------------

            elif subtype == "movement":

                operational_impact.append(
                    "Indicators suggest possible lateral movement across systems."
                )

                business_impact.append(
                    "Internal compromise may affect multiple business units."
                )

                propagation_paths.append(
                    "Compromised Host → Internal Network"
                )

                impact_score += 6

            # ------------------------------------------------
            # LEAK IMPACT
            # ------------------------------------------------

            elif subtype == "leak":

                business_impact.append(
                    "Sensitive information exposure may result in reputational damage."
                )

                operational_impact.append(
                    "Potential archival or dataset leakage identified."
                )

                compliance_impact.append(
                    "Possible GDPR/PII compliance exposure detected."
                )

                propagation_paths.append(
                    "Database → Leak Archive → External Distribution"
                )

                impact_score += 8

            # ------------------------------------------------
            # SALE IMPACT
            # ------------------------------------------------

            elif subtype == "sale":

                business_impact.append(
                    "Threat actor monetization activity detected."
                )

                operational_impact.append(
                    "Leaked assets may be redistributed across underground markets."
                )

                propagation_paths.append(
                    "Leak Distribution → Criminal Marketplace"
                )

                impact_score += 5

        # ----------------------------------------------------
        # EMAIL IMPACT
        # ----------------------------------------------------

        elif item_type == "email":

            email = item.get("value")

            affected_assets.append(email)

            if "admin" in email.lower():

                operational_impact.append(
                    "Administrative account exposure may enable privileged access."
                )

                impact_score += 4

        # ----------------------------------------------------
        # IPV4 IMPACT
        # ----------------------------------------------------

        elif item_type == "ipv4":

            ip = item.get("value")

            affected_assets.append(ip)

            operational_impact.append(
                "Suspicious external infrastructure identified."
            )

            impact_score += 2

    # ========================================================
    # IOC ENRICHMENT ANALYSIS
    # ========================================================

    for record in ioc_enrichment:

        risk = record.get("risk")

        if risk == "HIGH":
            impact_score += 5

        elif risk == "MEDIUM":
            impact_score += 3

    # ========================================================
    # THREAT LEVEL ADJUSTMENT
    # ========================================================

    if threat_level == "CRITICAL":
        impact_score += 10

    elif threat_level == "HIGH":
        impact_score += 6

    elif threat_level == "MEDIUM":
        impact_score += 3

    # ========================================================
    # DEDUPLICATION
    # ========================================================

    business_impact = list(set(business_impact))
    operational_impact = list(set(operational_impact))
    compliance_impact = list(set(compliance_impact))
    affected_assets = list(set(affected_assets))
    propagation_paths = list(set(propagation_paths))

    # ========================================================
    # CRITICALITY MAPPING
    # ========================================================

    if impact_score >= 30:
        criticality = "CRITICAL"

    elif impact_score >= 20:
        criticality = "HIGH"

    elif impact_score >= 10:
        criticality = "MEDIUM"

    else:
        criticality = "LOW"

    # ========================================================
    # FINAL OUTPUT
    # ========================================================

    return {

        "business_impact": business_impact,

        "operational_impact": operational_impact,

        "compliance_impact": compliance_impact,

        "affected_assets": affected_assets,

        "propagation_paths": propagation_paths,

        "impact_score": impact_score,

        "criticality": criticality
    }