"""
Validates the CVSS calculator against official NVD scores (O4).

1. Base score: recomputed from each NVD v3.1 vector and compared with
   the baseScore NVD published for it.
2. Environmental score with all Security Requirements = Medium (1.0)
   must equal the base score (spec property; holds for Scope Unchanged,
   as v3.1 uses a different modified-impact formula for Scope Changed).

Run from the project root:
    python -m engine.evaluation.cvss_validation
"""

import json

from engine.intelligence.cvss_impact import (
    NVD_RECENT,
    base_score,
    environmental_score,
    parse_vector
)


def main(path=NVD_RECENT):

    with open(path, "r", encoding="utf-8") as f:
        vulnerabilities = json.load(f)["vulnerabilities"]

    checked = matched = unchanged = env_equal = 0
    mismatches = []

    for item in vulnerabilities:

        for entry in item["cve"].get("metrics", {}).get("cvssMetricV31", []):

            data = entry["cvssData"]
            metrics = parse_vector(data["vectorString"])

            checked += 1

            if base_score(metrics) == data["baseScore"]:
                matched += 1

            elif len(mismatches) < 5:
                mismatches.append(
                    (data["vectorString"], data["baseScore"], base_score(metrics))
                )

            if metrics["S"] == "U":
                unchanged += 1
                env_equal += (
                    environmental_score(metrics, "M") == data["baseScore"]
                )

    print(f"[+] Base score vs NVD       : {matched}/{checked} exact matches")
    print(f"[+] Environmental(M) == base: {env_equal}/{unchanged} "
          f"(Scope Unchanged)")

    for vector, published, computed in mismatches:
        print(f"    mismatch {vector}: NVD {published}, computed {computed}")


if __name__ == "__main__":
    main()