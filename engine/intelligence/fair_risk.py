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

LEVELS = {1: "VERY LOW", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "VERY HIGH"}

INTENT = {"sale", "access", "creds", "leak"}        # what attackers do with it
CAPABILITY = {"exploit", "movement"}                # how they get in

SEVERITY_LEVEL = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2}
CRITICALITY_LEVEL = SEVERITY_LEVEL


def _band(value, edges):
    """1 + the number of edges the value reaches."""

    return 1 + sum(value >= edge for edge in edges)


def _risk_label(score):
    """Risk matrix (LEF level x LM level, 1..25) to the dashboard's scale."""

    if score <= 3:
        return "LOW"

    if score <= 8:
        return "MEDIUM"

    if score <= 15:
        return "HIGH"

    return "CRITICAL"


def threat_event_frequency(signals):

    n = len(signals)

    categories = {s.get("subtype") for s in signals}

    level = _band(n, (3, 6, 12, 20))

    both = bool(categories & INTENT) and bool(categories & CAPABILITY)

    if both:
        level = min(level + 1, 5)

    return level, {
        "signals": n,
        "intent_and_capability_seen": both,
        "basis": "signal count band, +1 when intent (sale/access/creds/leak) "
                 "and capability (exploit/movement) are both present",
    }


def vulnerability(cvss_impact, enriched_iocs):

    scenarios = cvss_impact.get("scenarios", [])

    top = max((s["environmental_score"] for s in scenarios), default=0.0)

    level = _band(top, (2, 4, 6, 8))

    known = any(i.get("kev") for i in enriched_iocs)

    if known:
        level = min(level + 1, 5)

    return level, {
        "highest_cvss_environmental_score": top,
        "known_exploited_cve": known,
        "basis": "CVSS v3.1 environmental score band, +1 for a CVE in the "
                 "CISA KEV catalogue",
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

    value = max(
        (CRITICALITY_LEVEL.get(a.get("criticality"), 1) for a in mapped_assets),
        default=1
    )

    kinds = {(a.get("asset_type"), a.get("asset_role")) for a in mapped_assets}

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
                "basis": "highest criticality among the mapped assets",
            },
            "breadth": {
                "level": breadth,
                "distinct_asset_kinds": len(kinds),
                "basis": "number of distinct asset types and roles touched",
            },
        },
    }
