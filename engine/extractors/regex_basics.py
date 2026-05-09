"""
Threat signal extraction engine.
"""

import re


def extract_basic(text):

    """
    Extracts threat indicators from text.
    """

    # ========================================================
    # NORMALIZE TEXT
    # ========================================================

    text = text.lower()

    # ========================================================
    # EMAIL EXTRACTION
    # ========================================================

    email_pattern = (
        r"[a-zA-Z0-9_.+-]+@"
        r"[a-zA-Z0-9-]+\."
        r"[a-zA-Z0-9-.]+"
    )

    # ========================================================
    # CVE EXTRACTION
    # ========================================================

    cve_pattern = r"cve-\d{4}-\d{4,7}"

    # ========================================================
    # IPV4 EXTRACTION
    # ========================================================

    ipv4_pattern = (
        r"\b(?:[0-9]{1,3}\.){3}"
        r"[0-9]{1,3}\b"
    )

    # ========================================================
    # API / THREAT INTELLIGENCE KEYWORDS
    # ========================================================

    keyword_patterns = {

        # ----------------------------------------------------
        # INITIAL ACCESS / ACCESS TOKENS / AUTH
        # ----------------------------------------------------

        "access": (
            r"(access|foothold|entry|shell|panel|"
            r"api key|apikey|jwt|oauth|token|"
            r"bearer token|session token)"
        ),

        # ----------------------------------------------------
        # CREDENTIALS / ACCOUNTS / TOKENS
        # ----------------------------------------------------

        "creds": (
            r"(creds|credentials|accounts|tokens|"
            r"records|secret|password|"
            r"admin account|user account)"
        ),

        # ----------------------------------------------------
        # EXPLOITATION / API ABUSE
        # ----------------------------------------------------

        "exploit": (
            r"(exploit|rce|vulnerability|struts|"
            r"patched|ssrf|injection|"
            r"deserialization|zero-day|"
            r"graphql|api exploit)"
        ),

        # ----------------------------------------------------
        # MOVEMENT / INTERNAL PIVOTING
        # ----------------------------------------------------

        "movement": (
            r"(lateral|pivot|internal|escalate|"
            r"internal api|privilege escalation)"
        ),

        # ----------------------------------------------------
        # DATA LEAK / EXPOSURE
        # ----------------------------------------------------

        "leak": (
            r"(leak|dump|archive|scrape|dataset|"
            r"ssn|exposure|customer data|"
            r"breach|data leak)"
        ),

        # ----------------------------------------------------
        # THREAT ACTOR MONETIZATION
        # ----------------------------------------------------

        "sale": (
            r"(sell|sale|crypto|btc|vendor|"
            r"marketplace|listing)"
        )
    }

    # ========================================================
    # EXTRACTION
    # ========================================================

    emails = list(
        set(
            re.findall(
                email_pattern,
                text
            )
        )
    )

    cves = list(
        set(
            re.findall(
                cve_pattern,
                text
            )
        )
    )

    ipv4s = list(
        set(
            re.findall(
                ipv4_pattern,
                text
            )
        )
    )

    keyword_hits = {}

    # ========================================================
    # KEYWORD EXTRACTION
    # ========================================================

    for category, pattern in keyword_patterns.items():

        matches = re.findall(
            pattern,
            text
        )

        if matches:

            keyword_hits[category] = list(
                set(matches)
            )

    # ========================================================
    # RETURN STRUCTURED RESULTS
    # ========================================================

    return {

        "emails": emails,

        "cves": cves,

        "ipv4": ipv4s,

        "keywords": keyword_hits
    }