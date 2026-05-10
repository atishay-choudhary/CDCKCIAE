"""
Consequence Cascade Engine

Responsible for:
- cascading impact modeling
- operational disruption analysis
- compliance escalation
- business consequence modeling
- downstream failure prediction
"""

# ============================================================
# CONSEQUENCE RULES
# ============================================================

CONSEQUENCE_RULES = {

    "Initial Access": [

        "Unauthorized system exposure",

        "Credential compromise risk"
    ],

    "Execution": [

        "Malicious code execution",

        "Endpoint compromise"
    ],

    "Privilege Escalation": [

        "Administrative takeover risk",

        "Security control bypass"
    ],

    "Credential Access": [

        "Credential theft exposure",

        "Identity compromise"
    ],

    "Lateral Movement": [

        "Internal network spread",

        "Multi-system compromise"
    ],

    "Collection": [

        "Sensitive data aggregation",

        "Internal reconnaissance"
    ],

    "Exfiltration": [

        "Sensitive data leakage",

        "Regulatory disclosure risk",

        "Customer data exposure"
    ],

    "Command and Control": [

        "Persistent attacker access",

        "Remote infrastructure control"
    ],

    "Defense Evasion": [

        "Reduced detection visibility",

        "Delayed incident response"
    ],

    "Persistence": [

        "Long-term environment compromise"
    ],

    "Monetization": [

        "Underground marketplace exposure",

        "Financial fraud risk",

        "Reputation damage"
    ]
}


# ============================================================
# BUSINESS IMPACT MAPPING
# ============================================================

BUSINESS_IMPACT = {

    "Sensitive data leakage": [

        "Customer trust degradation",

        "Brand reputation impact"
    ],

    "Customer data exposure": [

        "Regulatory investigation",

        "Legal liability exposure"
    ],

    "Administrative takeover risk": [

        "Critical infrastructure compromise",

        "Enterprise-wide disruption"
    ],

    "Internal network spread": [

        "Operational downtime",

        "Service interruption"
    ],

    "Persistent attacker access": [

        "Extended breach duration",

        "Repeated compromise risk"
    ]
}


# ============================================================
# COMPLIANCE IMPACT
# ============================================================

COMPLIANCE_MAPPING = {

    "Customer data exposure": [

        "GDPR exposure",

        "PCI-DSS compliance risk"
    ],

    "Sensitive data leakage": [

        "Data privacy violation risk"
    ],

    "Credential theft exposure": [

        "Identity protection compliance risk"
    ],

    "Financial fraud risk": [

        "Financial regulatory scrutiny"
    ]
}


# ============================================================
# GENERATE CONSEQUENCE MODEL
# ============================================================

def generate_consequence_model(

    propagation_results
):

    """
    Generates cascading
    consequence intelligence.
    """

    consequences = []

    seen = set()

    for propagation in propagation_results:

        path = propagation.get(

            "path",

            []
        )

        severity = propagation.get(

            "severity",

            "LOW"
        )

        probability = propagation.get(

            "probability",

            0.0
        )

        for stage in path:

            stage_consequences = CONSEQUENCE_RULES.get(

                stage,

                []
            )

            for consequence in stage_consequences:

                if consequence in seen:
                    continue

                seen.add(consequence)

                # ============================================
                # BUSINESS EFFECTS
                # ============================================

                business_effects = BUSINESS_IMPACT.get(

                    consequence,

                    []
                )

                # ============================================
                # COMPLIANCE EFFECTS
                # ============================================

                compliance_effects = COMPLIANCE_MAPPING.get(

                    consequence,

                    []
                )

                consequences.append({

                    "stage": stage,

                    "consequence": consequence,

                    "severity": severity,

                    "probability": probability,

                    "business_effects":
                        business_effects,

                    "compliance_effects":
                        compliance_effects
                })

    return consequences


# ============================================================
# SUMMARIZE CONSEQUENCES
# ============================================================

def summarize_consequences(

    consequence_results
):

    """
    Builds compact consequence summary.
    """

    summary = []

    for item in consequence_results:

        summary.append({

            "stage": item["stage"],

            "consequence":
                item["consequence"],

            "severity":
                item["severity"],

            "probability":
                item["probability"]
        })

    return summary


# ============================================================
# BUSINESS RISK SCORE
# ============================================================

def calculate_business_risk(

    consequence_results
):

    """
    Calculates organizational
    consequence risk score.
    """

    score = 0

    for item in consequence_results:

        severity = item["severity"]

        if severity == "CRITICAL":

            score += 10

        elif severity == "HIGH":

            score += 7

        elif severity == "MEDIUM":

            score += 4

        else:

            score += 1

    # ========================================================
    # RISK CLASSIFICATION
    # ========================================================

    if score >= 80:

        level = "CRITICAL"

    elif score >= 45:

        level = "HIGH"

    elif score >= 20:

        level = "MEDIUM"

    else:

        level = "LOW"

    return {

        "score": score,

        "risk_level": level
    }