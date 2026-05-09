"""
Main CLI entry point
for the C.D.K.C.I.A.E
Threat Intelligence Utility.
"""

# ------------------------------------------------------------
# Core Pipeline
# ------------------------------------------------------------

from engine.pipeline import run_pipeline

# ------------------------------------------------------------
# Intelligence Modules
# ------------------------------------------------------------

from engine.intelligence.killchain_mapper import (
    map_kill_chain
)

from engine.intelligence.threat_scorer import (
    calculate_threat_score
)

from engine.intelligence.narrative_generator import (
    generate_narrative
)

# ------------------------------------------------------------
# Reporting Module
# ------------------------------------------------------------

from engine.reports.report_generator import (
    generate_report
)


def main():

    # ========================================================
    # HEADER
    # ========================================================

    print("=" * 60)

    print("C.D.K.C.I.A.E Threat Intelligence Utility")

    print("=" * 60)

    # ========================================================
    # STEP 1 — Run Acquisition + Extraction Pipeline
    # ========================================================

    results = run_pipeline()

    # ========================================================
    # STEP 2 — Build Kill Chain
    # ========================================================

    kill_chain = map_kill_chain(results)

    # ========================================================
    # STEP 3 — Calculate Threat Severity
    # ========================================================

    threat_level = calculate_threat_score(results)

    # ========================================================
    # STEP 4 — Generate Intelligence Report
    # ========================================================

    generate_report(
        results,
        kill_chain,
        threat_level
    )

    # ========================================================
    # STEP 5 — Generate Threat Narrative
    # ========================================================

    narrative = generate_narrative(
        results,
        kill_chain,
        threat_level
    )

    print(narrative)

    # ========================================================
    # END
    # ========================================================

    print("\n[+] Intelligence Analysis Complete.\n")


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":

    main()