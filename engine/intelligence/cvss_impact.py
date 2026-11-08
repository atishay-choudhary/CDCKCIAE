"""
CVSS v3.1 environmental impact scoring (O4: FR-6.1 - FR-6.3).

Replaces the hand-assigned point weights in impact_engine with the
CVSS v3.1 environmental score (FIRST specification, sections 7.1-7.3):

- severity         : CVSS base metrics of each threat scenario
- asset importance : Security Requirements (CR / IR / AR) taken from
                     the mapped asset's criticality
- score bands      : the CVSS qualitative rating scale (section 5)

Two kinds of scenario are scored:
- a CVE found in the data: its real NVD v3.1 vector
- a signal class (access, leak, ...): an ASSUMED vector in the table
  below. These profiles are the only judgment calls in the model and
  are expressed in CVSS vocabulary so each can be audited and changed.

The headline score is the highest scenario score (CVSS practice is to
report the worst case). Exposure and attack probability are reported
beside it for explainability; they do not change the CVSS score.
"""

import math

from engine import datastore



# ----------------------------------------------------------------
# CVSS v3.1 specification constants
# ----------------------------------------------------------------
AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}
REQUIREMENT = {"L": 0.5, "M": 1.0, "H": 1.5}

# asset_mapper criticality -> Security Requirement
# (CVSS has no level above High; "M" is the Not Defined default)
CRITICALITY_TO_REQUIREMENT = {
    "LOW": "L",
    "MEDIUM": "M",
    "HIGH": "H",
    "CRITICAL": "H",
}

REQUIREMENT_RANK = {"L": 0, "M": 1, "H": 2}

# ----------------------------------------------------------------
# Assumed vectors per signal class (externally reachable, no
# privileges, except lateral movement which needs a foothold and
# crosses a security boundary).
# ----------------------------------------------------------------
SIGNAL_PROFILES = {
    "access": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "creds": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "exploit": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "movement": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    "leak": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "sale": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
}


def parse_vector(vector):

    return dict(
        part.split(":") for part in vector.split("/")
        if not part.startswith("CVSS:")
    )


def roundup(value):
    """
    CVSS v3.1 Roundup (floating-point safe), Appendix A.
    """

    integer = round(value * 100000)

    if integer % 10000 == 0:
        return integer / 100000.0

    return (math.floor(integer / 10000) + 1) / 10.0


def base_score(metrics):

    changed = metrics["S"] == "C"

    iss = 1 - (
        (1 - IMPACT[metrics["C"]])
        * (1 - IMPACT[metrics["I"]])
        * (1 - IMPACT[metrics["A"]])
    )

    impact = (
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        if changed
        else 6.42 * iss
    )

    exploitability = (
        8.22
        * AV[metrics["AV"]]
        * AC[metrics["AC"]]
        * (PR_CHANGED if changed else PR_UNCHANGED)[metrics["PR"]]
        * UI[metrics["UI"]]
    )

    if impact <= 0:
        return 0.0

    total = impact + exploitability

    return roundup(min(1.08 * total if changed else total, 10))


def environmental_score(metrics, requirement):
    """
    Modified metrics are Not Defined (= base metrics); the Security
    Requirement applies equally to C, I and A.
    """

    changed = metrics["S"] == "C"

    weight = REQUIREMENT[requirement]

    miss = min(
        1 - (
            (1 - IMPACT[metrics["C"]] * weight)
            * (1 - IMPACT[metrics["I"]] * weight)
            * (1 - IMPACT[metrics["A"]] * weight)
        ),
        0.915
    )

    impact = (
        7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13
        if changed
        else 6.42 * miss
    )

    exploitability = (
        8.22
        * AV[metrics["AV"]]
        * AC[metrics["AC"]]
        * (PR_CHANGED if changed else PR_UNCHANGED)[metrics["PR"]]
        * UI[metrics["UI"]]
    )

    if impact <= 0:
        return 0.0

    total = impact + exploitability

    return roundup(roundup(min(1.08 * total if changed else total, 10)))


def rating(score):
    """
    CVSS v3.1 qualitative severity rating scale (section 5).
    """

    if score >= 9.0:
        return "CRITICAL"

    if score >= 7.0:
        return "HIGH"

    if score >= 4.0:
        return "MEDIUM"

    if score > 0.0:
        return "LOW"

    return "NONE"


def cve_vectors(cve_ids):
    """
    {CVE-ID: v3.1 vector} for the ids present in the nvd_record table.
    """

    if not cve_ids:
        return {}

    return {
        cve_id: record["metrics"]["cvssMetricV31"][0]["cvssData"]["vectorString"]
        for cve_id, record in datastore.nvd_by_ids(cve_ids).items()
        if record.get("metrics", {}).get("cvssMetricV31")
    }


def assess_cvss_impact(
    results,
    correlations,
    mapped_assets,
    path_prediction=None
):

    # Highest requirement per asset role; worst case over all assets
    # is used for CVE scenarios, which are not tied to a role.
    role_requirement = {}

    for asset in mapped_assets:

        # keyword signals are not assets and carry no requirement
        if asset["criticality"] not in CRITICALITY_TO_REQUIREMENT:
            continue

        level = CRITICALITY_TO_REQUIREMENT[asset["criticality"]]
        role = asset["asset_role"]

        if REQUIREMENT_RANK[level] > REQUIREMENT_RANK[
            role_requirement.get(role, "L")
        ] or role not in role_requirement:
            role_requirement[role] = level

    # no identified enterprise asset means no evidence that anything
    # valuable is affected: the Security Requirement is Low, not the
    # Not Defined (Medium) default
    worst = max(
        role_requirement.values(),
        key=REQUIREMENT_RANK.get,
        default="L"
    )

    scenarios = []

    def add(name, source, vector, requirement, requirement_source):

        metrics = parse_vector(vector)

        scenarios.append({
            "scenario": name,
            "source": source,
            "vector": vector,
            "base_score": base_score(metrics),
            "security_requirement": requirement,
            "requirement_source": requirement_source,
            "environmental_score": environmental_score(metrics, requirement)
        })

    subtypes = {
        r["subtype"] for r in results
        if r["type"] == "keyword" and r["subtype"] in SIGNAL_PROFILES
    }

    for subtype in sorted(subtypes):

        add(
            subtype,
            "assumed profile",
            SIGNAL_PROFILES[subtype],
            worst,
            "worst-case asset" if role_requirement else "no asset identified"
        )

    cves = {r["value"].upper() for r in results if r["type"] == "cve"}

    for cve_id, vector in sorted(cve_vectors(cves).items()):

        add(
            cve_id,
            "NVD vector",
            vector,
            worst,
            "worst-case asset" if role_requirement else "no asset identified"
        )

    scenarios.sort(key=lambda s: -s["environmental_score"])

    score = scenarios[0]["environmental_score"] if scenarios else 0.0

    # Paths are ordered by earliest observed stage, then likelihood:
    # the first is the most likely path from the earliest entry.
    top_path = (
        path_prediction["paths"][0]
        if path_prediction and path_prediction.get("paths")
        else None
    )

    return {
        "impact_score": score,
        "criticality": rating(score),
        "scenarios": scenarios,
        "factors": {
            "severity": scenarios[0]["base_score"] if scenarios else 0.0,
            "asset_importance": (
                scenarios[0]["security_requirement"] if scenarios else None
            ),
            "exposure": {
                "emails": sum(r["type"] == "email" for r in results),
                "ipv4": sum(r["type"] == "ipv4" for r in results),
                "cves": len(cves),
                "known_exploited": sum(
                    c["type"] == "kev_correlation" for c in correlations
                )
            },
            "attack_probability": (
                {
                    "path": " -> ".join(top_path["path"]),
                    "likelihood": top_path["likelihood"]
                }
                if top_path else None
            )
        }
    }
