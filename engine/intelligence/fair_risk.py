"""
Business risk and enterprise exposure on a simplified Open FAIR model
(SRS FR-6.1 / FR-6.2: values traceable to a recognised standard).

FAIR decomposes risk into how often a loss happens and how bad it is:

    Risk = Loss Event Frequency (LEF) x Loss Magnitude (LM)
    LEF  = Threat Event Frequency (TEF) and Vulnerability (Vuln)
    LM   = the larger of primary loss and secondary loss

Every factor is an ordinal level 1 (very low) to 5 (very high), the
qualitative form of Open FAIR, derived from observed evidence. No
currency amounts are invented: dollar-valued FAIR needs the
organisation's own loss data. Each factor returns its level and the
evidence behind it, so a score can be traced back in the report.
"""

from urllib.parse import urlsplit

LEVELS = {1: "VERY LOW", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "VERY HIGH"}

INTENT = {"sale", "access", "creds", "leak"}        # what attackers do with it
CAPABILITY = {"exploit", "movement"}                # how they get in

SEVERITY_LEVEL = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2}
CRITICALITY_LEVEL = SEVERITY_LEVEL


def _band(value, edges):
    """1 + the number of edges the value reaches."""

    return 1 + sum(value >= edge for edge in edges)


def _risk_label(score):
    """
    Risk matrix (LEF level x LM level, 1..25) to the dashboard's scale.
    CRITICAL needs a level-5 factor against a level-4 or higher one
    (5x4 = 20); 4x4 is HIGH.
    """

    if score <= 3:
        return "LOW"

    if score <= 9:
        return "MEDIUM"

    if score <= 16:
        return "HIGH"

    return "CRITICAL"


def _site(source):
    """The site a signal came from: many searches on one site are one source."""

    return urlsplit(source or "").netloc or (source or "")


def threat_event_frequency(signals):

    sites = {_site(s.get("source")) for s in signals if s.get("source")}

    categories = {s.get("subtype") for s in signals if s.get("subtype")}

    # corroboration across sites counts for more than repetition on one
    # page, and breadth of activity for more than the number of words
    corroboration = _band(len(sites), (2, 3, 5, 8))

    breadth = _band(len(categories), (2, 3, 4, 6))

    level = (corroboration + breadth + 1) // 2

    both = bool(categories & INTENT) and bool(categories & CAPABILITY)

    if both:
        level = min(level + 1, 5)

    return level, {
        "signals": len(signals),
        "distinct_sources": len(sites),
        "distinct_categories": len(categories),
        "intent_and_capability_seen": both,
        "basis": "mean of a distinct-site band and a distinct-category band, "
                 "+1 when intent (sale/access/creds/leak) and capability "
                 "(exploit/movement) are both present",
    }


def vulnerability(cvss_impact, enriched_iocs):
    """
    Only a CVE with a real NVD vector is evidence of a vulnerability.
    The assumed signal profiles describe what an attacker could do, which
    the threat event frequency already covers, so they do not count here.
    """

    scenarios = cvss_impact.get("scenarios", [])

    cve_scores = [
        s["environmental_score"] for s in scenarios
        if s.get("source", "NVD vector") == "NVD vector"
    ]

    top = max(cve_scores, default=0.0)

    if cve_scores:
        level = _band(top, (2, 4, 6, 8))

    else:
        # nothing confirmed, but attacker activity was seen
        level = 2 if scenarios else 1

    known = any(i.get("kev") for i in enriched_iocs)

    if known:
        level = min(level + 1, 5)

    return level, {
        "highest_cvss_environmental_score": top,
        "confirmed_cves": len(cve_scores),
        "known_exploited_cve": known,
        "basis": "environmental CVSS v3.1 score band of CVEs with an NVD "
                 "vector, +1 for a CVE in the CISA KEV catalogue; level 2 "
                 "when attacker activity is seen but no CVE is confirmed",
    }


def primary_loss(consequences):

    level = max(
        (SEVERITY_LEVEL.get(c.get("severity"), 1) for c in consequences),
        default=1
    )

    return level, {
        "consequences": len(consequences),
        "basis": "most severe consequence the propagation paths lead to",
    }


def secondary_loss(consequences):

    effects = {
        e for c in consequences for e in c.get("compliance_effects", [])
    }

    return _band(len(effects), (1, 2, 4, 6)), {
        "compliance_effects": sorted(effects),
        "basis": "number of distinct regulatory / compliance effects",
    }


def assess_business_risk(signals, consequences, cvss_impact, enriched_iocs):

    tef, tef_evidence = threat_event_frequency(signals)
    vuln, vuln_evidence = vulnerability(cvss_impact, enriched_iocs)
    primary, primary_evidence = primary_loss(consequences)
    secondary, secondary_evidence = secondary_loss(consequences)

    lef = (tef + vuln + 1) // 2
    magnitude = max(primary, secondary)
    score = lef * magnitude

    return {
        "model": "simplified Open FAIR (ordinal levels 1-5)",
        "score": score,
        "max_score": 25,
        "risk_level": _risk_label(score),
        "factors": {
            "threat_event_frequency": {"level": tef, **tef_evidence},
            "vulnerability": {"level": vuln, **vuln_evidence},
            "loss_event_frequency": {
                "level": lef, "basis": "mean of TEF and vulnerability levels, rounded up"
            },
            "primary_loss": {"level": primary, **primary_evidence},
            "secondary_loss": {"level": secondary, **secondary_evidence},
            "loss_magnitude": {
                "level": magnitude, "basis": "larger of primary and secondary"
            },
        },
    }


def assess_exposure(mapped_assets):
    """Asset value x how many distinct kinds of asset are touched."""

    # keyword signals are unrated: only real assets count
    assets = [
        a for a in mapped_assets if a.get("criticality") in CRITICALITY_LEVEL
    ]

    value = max(
        (CRITICALITY_LEVEL[a["criticality"]] for a in assets), default=1
    )

    kinds = {(a.get("asset_type"), a.get("asset_role")) for a in assets}

    breadth = _band(len(kinds), (2, 4, 6, 8))

    score = value * breadth

    return {
        "model": "asset value x breadth (ordinal levels 1-5)",
        "exposure_score": score,
        "max_score": 25,
        "exposure_level": _risk_label(score),
        "factors": {
            "asset_value": {
                "level": value,
                "basis": "highest criticality among the rated assets (emails, IPs, confirmed CVEs)",
            },
            "breadth": {
                "level": breadth,
                "distinct_asset_kinds": len(kinds),
                "basis": "number of distinct asset types and roles touched",
            },
        },
    }
