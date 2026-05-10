"""
Asset Mapping Engine

Responsible for:
- infrastructure classification
- business unit mapping
- asset criticality scoring
- infrastructure context generation
- enterprise asset correlation
"""

# ============================================================
# BUSINESS UNIT MAPPING
# ============================================================

BUSINESS_UNIT_RULES = {

    "support": "Customer Support Operations",

    "admin": "Administrative Infrastructure",

    "core": "Core Enterprise Systems",

    "finance": "Financial Operations",

    "billing": "Billing Infrastructure",

    "hr": "Human Resources Systems",

    "dev": "Development Infrastructure",

    "api": "API Gateway Infrastructure",

    "db": "Database Infrastructure",

    "mail": "Enterprise Mail Systems"
}

# ============================================================
# ASSET CRITICALITY RULES
# ============================================================

CRITICALITY_RULES = {

    "admin": "CRITICAL",

    "core": "CRITICAL",

    "db": "HIGH",

    "finance": "HIGH",

    "billing": "HIGH",

    "support": "MEDIUM",

    "api": "HIGH",

    "mail": "MEDIUM",

    "dev": "MEDIUM"
}

# ============================================================
# INFRASTRUCTURE TAGS
# ============================================================

INFRASTRUCTURE_TAGS = {

    "ipv4": "Network Infrastructure",

    "email": "Enterprise Communication Asset",

    "cve": "Vulnerable Technology Asset"
}

# ============================================================
# MAP ENTERPRISE ASSETS
# ============================================================

def map_assets(

    results,

    enriched_iocs=None
):

    """
    Maps indicators to
    enterprise assets.
    """

    if enriched_iocs is None:

        enriched_iocs = []

    mapped_assets = []

    seen = set()

    # ========================================================
    # PROCESS RESULTS
    # ========================================================

    for item in results:

        item_type = item.get(

            "type",

            "unknown"
        )

        value = item.get(

            "value",

            "unknown"
        )

        unique_key = (

            item_type,

            value
        )

        if unique_key in seen:
            continue

        seen.add(unique_key)

        # ====================================================
        # DEFAULTS
        # ====================================================

        business_unit = "General Infrastructure"

        criticality = "LOW"

        infrastructure = INFRASTRUCTURE_TAGS.get(

            item_type,

            "Generic Infrastructure"
        )

        asset_role = "Unknown"

        # ====================================================
        # EMAIL ANALYSIS
        # ====================================================

        if item_type == "email":

            lower_value = value.lower()

            for keyword, unit in BUSINESS_UNIT_RULES.items():

                if keyword in lower_value:

                    business_unit = unit

                    asset_role = keyword

                    criticality = CRITICALITY_RULES.get(

                        keyword,

                        "MEDIUM"
                    )

                    break

        # ====================================================
        # IPV4 ANALYSIS
        # ====================================================

        elif item_type == "ipv4":

            infrastructure = "External Network Infrastructure"

            criticality = "MEDIUM"

            asset_role = "network-node"

        # ====================================================
        # CVE ANALYSIS
        # ====================================================

        elif item_type == "cve":

            infrastructure = "Vulnerable Enterprise Technology"

            criticality = "HIGH"

            asset_role = "software-stack"

        # ====================================================
        # KEYWORD ANALYSIS
        # ====================================================

        elif item_type == "keyword":

            subtype = item.get(

                "subtype",

                "unknown"
            )

            asset_role = subtype

            if subtype == "access":

                criticality = "HIGH"

            elif subtype == "movement":

                criticality = "CRITICAL"

            elif subtype == "leak":

                criticality = "CRITICAL"

            elif subtype == "sale":

                criticality = "HIGH"

        # ====================================================
        # BUILD ASSET RECORD
        # ====================================================

        mapped_assets.append({

            "asset": value,

            "asset_type": item_type,

            "business_unit": business_unit,

            "infrastructure": infrastructure,

            "asset_role": asset_role,

            "criticality": criticality
        })

    return mapped_assets


# ============================================================
# SUMMARIZE ASSETS
# ============================================================

def summarize_assets(

    mapped_assets
):

    """
    Builds compact asset summary.
    """

    summary = []

    for item in mapped_assets:

        summary.append({

            "asset": item["asset"],

            "business_unit":
                item["business_unit"],

            "criticality":
                item["criticality"],

            "role":
                item["asset_role"]
        })

    return summary


# ============================================================
# CALCULATE ENTERPRISE EXPOSURE
# ============================================================

def calculate_enterprise_exposure(

    mapped_assets
):

    """
    Calculates enterprise
    infrastructure exposure.
    """

    score = 0

    for item in mapped_assets:

        criticality = item["criticality"]

        if criticality == "CRITICAL":

            score += 10

        elif criticality == "HIGH":

            score += 7

        elif criticality == "MEDIUM":

            score += 4

        else:

            score += 1

    # ========================================================
    # EXPOSURE CLASSIFICATION
    # ========================================================

    if score >= 80:

        exposure = "CRITICAL"

    elif score >= 45:

        exposure = "HIGH"

    elif score >= 20:

        exposure = "MEDIUM"

    else:

        exposure = "LOW"

    return {

        "exposure_score": score,

        "exposure_level": exposure
    }