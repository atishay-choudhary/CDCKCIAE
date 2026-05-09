"""
IOC Enrichment Engine
"""

import ipaddress
import socket
from urllib.parse import urlparse


# ============================================================
# SUSPICIOUS TLDS
# ============================================================

SUSPICIOUS_TLDS = {

    ".ru",
    ".xyz",
    ".top",
    ".onion",
    ".cc",
    ".su"
}

# ============================================================
# ROLE ACCOUNTS
# ============================================================

ROLE_ACCOUNTS = {

    "admin",
    "support",
    "root",
    "security",
    "info",
    "helpdesk"
}


# ============================================================
# IP ENRICHMENT
# ============================================================

def enrich_ip(ip):

    """
    Enrich IPv4 indicators.
    """

    enrichment = {

        "ioc_type": "ipv4",

        "value": ip,

        "is_private": False,

        "is_reserved": False,

        "classification": "unknown",

        "risk": "low"
    }

    try:

        obj = ipaddress.ip_address(ip)

        enrichment["is_private"] = obj.is_private

        enrichment["is_reserved"] = obj.is_reserved

        # ----------------------------------------------------
        # CLASSIFICATION
        # ----------------------------------------------------

        if obj.is_private:

            enrichment["classification"] = "internal"

            enrichment["risk"] = "low"

        else:

            enrichment["classification"] = "public"

            enrichment["risk"] = "medium"

    except Exception:

        enrichment["classification"] = "invalid"

        enrichment["risk"] = "high"

    return enrichment


# ============================================================
# EMAIL ENRICHMENT
# ============================================================

def enrich_email(email):

    """
    Enrich email indicators.
    """

    enrichment = {

        "ioc_type": "email",

        "value": email,

        "domain": None,

        "role_account": False,

        "risk": "low"
    }

    try:

        local, domain = email.split("@")

        enrichment["domain"] = domain

        # ----------------------------------------------------
        # ROLE ACCOUNT DETECTION
        # ----------------------------------------------------

        if local.lower() in ROLE_ACCOUNTS:

            enrichment["role_account"] = True

            enrichment["risk"] = "medium"

    except Exception:

        enrichment["risk"] = "high"

    return enrichment


# ============================================================
# DOMAIN ENRICHMENT
# ============================================================

def enrich_domain(domain):

    """
    Enrich domain indicators.
    """

    enrichment = {

        "ioc_type": "domain",

        "value": domain,

        "resolved_ip": None,

        "suspicious_tld": False,

        "risk": "low"
    }

    try:

        # ----------------------------------------------------
        # DNS RESOLUTION
        # ----------------------------------------------------

        resolved_ip = socket.gethostbyname(domain)

        enrichment["resolved_ip"] = resolved_ip

        # ----------------------------------------------------
        # SUSPICIOUS TLD CHECK
        # ----------------------------------------------------

        for tld in SUSPICIOUS_TLDS:

            if domain.endswith(tld):

                enrichment["suspicious_tld"] = True

                enrichment["risk"] = "high"

    except Exception:

        enrichment["risk"] = "medium"

    return enrichment


# ============================================================
# CVE ENRICHMENT
# ============================================================

def enrich_cve(cve, correlations):

    """
    Enrich CVE indicators from correlations.
    """

    enrichment = {

        "ioc_type": "cve",

        "value": cve,

        "severity": "UNKNOWN",

        "kev": False,

        "risk": "medium"
    }

    for item in correlations:

        # ----------------------------------------------------
        # CVE MATCH
        # ----------------------------------------------------

        if item.get("type") == "cve_correlation":

            if item.get("cve", "").lower() == cve.lower():

                enrichment["severity"] = item.get(

                    "severity",

                    "UNKNOWN"
                )

        # ----------------------------------------------------
        # KEV MATCH
        # ----------------------------------------------------

        if item.get("type") == "kev_correlation":

            if item.get("cve", "").lower() == cve.lower():

                enrichment["kev"] = True

                enrichment["risk"] = "critical"

    return enrichment


# ============================================================
# MASTER ENRICHMENT
# ============================================================

def enrich_iocs(signals, correlations):

    """
    Enrich all extracted IOCs.
    """

    enriched = []

    for signal in signals:

        signal_type = signal.get("type")

        value = signal.get("value")

        # ----------------------------------------------------
        # IPV4
        # ----------------------------------------------------

        if signal_type == "ipv4":

            enriched.append(

                enrich_ip(value)
            )

        # ----------------------------------------------------
        # EMAIL
        # ----------------------------------------------------

        elif signal_type == "email":

            enriched.append(

                enrich_email(value)
            )

        # ----------------------------------------------------
        # CVE
        # ----------------------------------------------------

        elif signal_type == "cve":

            enriched.append(

                enrich_cve(
                    value,
                    correlations
                )
            )

    return enriched