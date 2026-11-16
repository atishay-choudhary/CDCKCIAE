"""
Entity extraction module.

Extracts:
- emails
- IPs
- CVEs
- domains
"""

import re

from engine.nlp.entity_filters import valid_domain


# ============================================================
# PATTERNS
# ============================================================

EMAIL_PATTERN = (

    r"[a-zA-Z0-9_.+-]+@"
    r"[a-zA-Z0-9-]+\."
    r"[a-zA-Z0-9-.]+"
)

IPV4_PATTERN = (

    r"\b(?:[0-9]{1,3}\.){3}"
    r"[0-9]{1,3}\b"
)

CVE_PATTERN = (

    r"CVE-\d{4}-\d{4,7}"
)

DOMAIN_PATTERN = (

    r"\b(?:[a-zA-Z0-9-]+\.)+"
    r"[a-zA-Z]{2,}\b"
)


# ============================================================
# ENTITY EXTRACTION
# ============================================================

def extract_entities(text):

    """
    Extracts intelligence entities.
    """

    emails = list(

        set(

            re.findall(
                EMAIL_PATTERN,
                text,
                re.IGNORECASE
            )
        )
    )

    ipv4 = list(

        set(

            re.findall(
                IPV4_PATTERN,
                text
            )
        )
    )

    cves = list(

        set(

            re.findall(
                CVE_PATTERN,
                text,
                re.IGNORECASE
            )
        )
    )

    # only real-looking domains: org.minidns.record or dump.zip are not
    domains = list(

        {
            d.lower(): d
            for d in re.findall(
                DOMAIN_PATTERN,
                text,
                re.IGNORECASE
            )
            if valid_domain(d)
        }.values()
    )

    return {

        "emails": emails,

        "ipv4": ipv4,

        "cves": cves,

        "domains": domains
    }