"""
Threat keyword analysis module.
"""

from collections import Counter


# ============================================================
# THREAT CATEGORIES
# ============================================================

THREAT_TERMS = {

    "access": [

        "access",
        "entry",
        "foothold",
        "shell",
        "token",
        "apikey",
        "jwt"
    ],

    "exploit": [

        "exploit",
        "rce",
        "vulnerability",
        "struts",
        "ssrf",
        "injection"
    ],

    "movement": [

        "pivot",
        "internal",
        "lateral",
        "escalate"
    ],

    "leak": [

        "leak",
        "dump",
        "dataset",
        "archive",
        "scrape",
        "breach"
    ],

    "sale": [

        "crypto",
        "vendor",
        "listing",
        "sell",
        "marketplace"
    ]
}


# ============================================================
# KEYWORD ANALYSIS
# ============================================================

def analyze_keywords(tokens):

    """
    Detects threat keyword frequency.
    """

    findings = {}

    token_counts = Counter(tokens)

    for category, terms in THREAT_TERMS.items():

        category_hits = {}

        for term in terms:

            if term in token_counts:

                category_hits[term] = token_counts[
                    term
                ]

        if category_hits:

            findings[category] = category_hits

    return findings