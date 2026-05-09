"""
Threat signal extraction engine.
"""

import re


def extract_basic(text):

    """
    Extracts threat indicators from text.
    """

    text = text.lower()

    # Email extraction
    email_pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"

    # CVE extraction
    cve_pattern = r"cve-\d{4}-\d{4,7}"

    # IPv4 extraction
    ipv4_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

    # Threat keyword groups
    keyword_patterns = {

        "access": r"(access|foothold|entry|shell|panel)",

        "creds": r"(creds|credentials|accounts|tokens|records)",

        "exploit": r"(exploit|rce|vulnerability|struts|patched)",

        "movement": r"(lateral|pivot|internal|escalate)",

        "leak": r"(leak|dump|archive|scrape|dataset|ssn)",

        "sale": r"(sell|sale|crypto|btc|vendor)"
    }

    emails = list(set(re.findall(email_pattern, text)))

    cves = list(set(re.findall(cve_pattern, text)))

    ipv4s = list(set(re.findall(ipv4_pattern, text)))

    keyword_hits = {}

    # Extract threat keywords
    for category, pattern in keyword_patterns.items():

        matches = re.findall(pattern, text)

        if matches:
            keyword_hits[category] = list(set(matches))

    return {
        "emails": emails,
        "cves": cves,
        "ipv4": ipv4s,
        "keywords": keyword_hits
    }