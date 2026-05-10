"""
Main CLI entry point
for the C.D.K.C.I.A.E
Threat Intelligence Utility.
"""


# ============================================================
# IMPORTING FOR VISUALS ON TERMINAL
# ============================================================
import os
from pyfiglet import Figlet
from colorama import Fore, Style, init

# ============================================================
# CORE PIPELINE
# ============================================================

from engine.pipeline import run_pipeline

# ============================================================
# DATASET LOADERS
# ============================================================

from engine.datasets.dataset_loader import (

    load_cve_dataset,

    load_mitre_dataset,

    load_kev_dataset,

    load_historical_attacks
)

# ============================================================
# INTELLIGENCE MODULES
# ============================================================

from engine.intelligence.killchain_mapper import (
    map_kill_chain
)

from engine.intelligence.threat_scorer import (
    calculate_threat_score
)

from engine.intelligence.narrative_generator import (
    generate_narrative
)

# ============================================================
# INTELLIGENCE SUMMARY MODULE
# ============================================================

from engine.intelligence.intelligence_summary import (

    summarize_findings,

    group_nlp_categories,

    compact_mitre_output,

    build_executive_summary
)

# ============================================================
# PDF REPORT MODULE
# ============================================================

from engine.reports.report_generator import (
    generate_pdf_report
)

# ============================================================
# GRAPH MODULES
# ============================================================

from engine.graph.graph_visualizer import (
    visualize_graph
)


# ============================================================
# MAIN
# ============================================================

def main():

    # ========================================================
    # HEADER
    # ========================================================

    print("=" * 60)

    # print("C.D.K.C.I.A.E Threat Intelligence Utility")
    init(autoreset=True)

    os.system("cls" if os.name == "nt" else "clear")

    f = Figlet(font="slant")

    banner = f.renderText("C.D.K.C.I.A.E")

    print(Fore.CYAN + "=" * 75)
    print(Fore.RED + banner)
    print(Fore.YELLOW + "        Crodd Domain Kill-Chain Impact Assessment Engine")
    print(Fore.CYAN + "=" * 75)

    print(Fore.GREEN + """
    ╔══════════════════════════════════════════════════════════════════════╗
    ║                                                                      ║
    ║                   CYBER THREAT INTELLIGENCE FRAMEWORK                ║
    ║                                                                      ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)

    print("=" * 60)

    # ========================================================
    # DATASET STATUS
    # ========================================================

    print("\n[DATASET STATUS]\n")

    cve_data = load_cve_dataset()

    mitre_data = load_mitre_dataset()

    kev_data = load_kev_dataset()

    historical_data = load_historical_attacks()

    print(
        f"✔ CVE Intelligence Loaded "
        f"({len(cve_data)} records)"
    )

    print(
        f"✔ MITRE ATT&CK Loaded "
        f"({len(mitre_data)} techniques)"
    )

    print(
        f"✔ KEV Database Loaded "
        f"({len(kev_data)} entries)"
    )

    print(
        f"✔ Historical Threat Dataset Loaded "
        f"({len(historical_data)} attacks)"
    )

    # ========================================================
    # RUN PIPELINE
    # ========================================================

    pipeline_output = run_pipeline()

    # ========================================================
    # EXTRACT OUTPUTS
    # ========================================================

    results = pipeline_output["signals"]

    correlations = pipeline_output["correlations"]

    important_terms = pipeline_output[
        "important_terms"
    ]

    mitre_dataset = pipeline_output[
        "mitre_dataset"
    ]

    threat_graph = pipeline_output[
        "threat_graph"
    ]

    enriched_iocs = pipeline_output[
        "enriched_iocs"
    ]

    impact_analysis = pipeline_output[
        "impact_analysis"
    ]

    propagation_results = pipeline_output[
        "propagation_results"
    ]

    propagation_summary = pipeline_output[
        "propagation_summary"
    ]

    consequence_results = pipeline_output[
        "consequence_results"
    ]

    consequence_summary = pipeline_output[
        "consequence_summary"
    ]

    business_risk = pipeline_output[
        "business_risk"
    ]

    mapped_assets = pipeline_output[
        "mapped_assets"
    ]

    asset_summary = pipeline_output[
        "asset_summary"
    ]

    enterprise_exposure = pipeline_output[
        "enterprise_exposure"
    ]

    # ========================================================
    # BUILD KILL CHAIN
    # ========================================================

    kill_chain = map_kill_chain(

        results,

        correlations
    )

    # ========================================================
    # ORDERED KILL CHAIN
    # ========================================================

    ordered_chain = [

        "Initial Access",

        "Execution",

        "Privilege Escalation",

        "Exfiltration",

        "Monetization"
    ]

    visible_chain = [

        stage for stage in ordered_chain

        if stage in kill_chain
    ]

    # ========================================================
    # THREAT SCORE
    # ========================================================

    threat_level = calculate_threat_score(

        results,

        correlations
    )

    # ========================================================
    # BUILD SUMMARIES
    # ========================================================

    executive_summary = build_executive_summary(

        threat_level,

        visible_chain
    )

    findings = summarize_findings(
        results
    )

    nlp_groups = group_nlp_categories(
        correlations
    )

    mitre_summary = compact_mitre_output(
        mitre_dataset
    )

    # ========================================================
    # PIPELINE STATUS
    # ========================================================

    print("\n[PIPELINE STATUS]\n")

    print("✔ Threat Crawling Complete")

    print("✔ Signal Extraction Complete")

    print("✔ NLP Analysis Complete")

    print("✔ Correlation Analysis Complete")

    print("✔ IOC Enrichment Complete")

    print("✔ Cross-Domain Impact Analysis Complete")

    print("✔ Propagation Simulation Complete")

    print("✔ Consequence Cascade Analysis Complete")

    print("✔ Enterprise Asset Mapping Complete")

    print("✔ Graph Intelligence Built")

    print("✔ Reporting Engine Ready")

    # ========================================================
    # NARRATIVE
    # ========================================================

    narrative = generate_narrative(

        results,

        visible_chain,

        threat_level,

        correlations
    )

    # ========================================================
    # THREAT ASSESSMENT SUMMARY
    # ========================================================

    print("\n")

    print("=" * 60)

    print("THREAT ASSESSMENT SUMMARY")

    print("=" * 60)

    print(f"\nThreat Level: {threat_level}")

    print("\nKill Chain Progression:")

    print(

        " → ".join(visible_chain)
    )

    print("\nExecutive Assessment:\n")

    for line in executive_summary:

        print(f"• {line}")

    # ========================================================
    # KEY FINDINGS
    # ========================================================

    print("\n")

    print("=" * 60)

    print("KEY INTELLIGENCE FINDINGS")

    print("=" * 60)

    for finding in findings:

        print(f"\n✔ {finding}")

    # ========================================================
    # IOC ENRICHMENT SUMMARY
    # ========================================================

    print("\n")

    print("=" * 60)

    print("IOC ENRICHMENT SUMMARY")

    print("=" * 60)

    if enriched_iocs:

        for item in enriched_iocs:

            print("\n----------------------------------------")

            print(
                f"IOC      : {item.get('value', 'UNKNOWN')}"
            )

            print(
                f"TYPE     : {item.get('ioc_type', 'UNKNOWN').upper()}"
            )

            print(
                f"RISK     : {item.get('risk', 'UNKNOWN').upper()}"
            )

            if item.get("domain"):

                print(
                    f"DOMAIN   : {item['domain']}"
                )

            if item.get("role_account"):

                print(
                    "ROLE ACC : TRUE"
                )

            if item.get("classification"):

                print(
                    f"CLASS    : {item['classification']}"
                )

            if item.get("severity"):

                print(
                    f"SEVERITY : {item['severity']}"
                )

            if item.get("kev"):

                print(
                    "KEV      : TRUE"
                )

    else:

        print("\nNo enrichment records available.")

    # ========================================================
    # CROSS-DOMAIN IMPACT ANALYSIS
    # ========================================================

    print("\n")

    print("=" * 60)

    print("CROSS-DOMAIN IMPACT ANALYSIS")

    print("=" * 60)

    print(
        f"\nImpact Criticality: "
        f"{impact_analysis['criticality']}"
    )

    print(
        f"Impact Score: "
        f"{impact_analysis['impact_score']}"
    )

    # ========================================================
    # PROPAGATION ANALYSIS
    # ========================================================

    print("\n")

    print("=" * 60)

    print("PROPAGATION ANALYSIS")

    print("=" * 60)

    if propagation_summary:

        for item in propagation_summary[:5]:

            print("\n----------------------------------------")

            print(
                f"Path        : {item['path']}"
            )

            print(
                f"Probability : {item['probability']}"
            )

            print(
                f"Severity    : {item['severity']}"
            )

            print(
                f"Depth       : {item['depth']}"
            )

    else:

        print("\nNo propagation intelligence available.")

    # ========================================================
    # CONSEQUENCE ANALYSIS
    # ========================================================

    print("\n")

    print("=" * 60)

    print("CONSEQUENCE ANALYSIS")

    print("=" * 60)

    if consequence_results:

        for item in consequence_results[:8]:

            print("\n----------------------------------------")

            print(
                f"Stage       : {item['stage']}"
            )

            print(
                f"Consequence : {item['consequence']}"
            )

            print(
                f"Severity    : {item['severity']}"
            )

            print(
                f"Probability : {item['probability']}"
            )

    else:

        print("\nNo consequence intelligence available.")

    # ========================================================
    # BUSINESS RISK SUMMARY
    # ========================================================

    print("\n")

    print("=" * 60)

    print("BUSINESS RISK SUMMARY")

    print("=" * 60)

    print(
        f"\nBusiness Risk Score : "
        f"{business_risk['score']}"
    )

    print(
        f"Business Risk Level : "
        f"{business_risk['risk_level']}"
    )

    # ========================================================
    # ENTERPRISE ASSET INTELLIGENCE
    # ========================================================

    print("\n")

    print("=" * 60)

    print("ENTERPRISE ASSET INTELLIGENCE")

    print("=" * 60)

    if mapped_assets:

        for asset in mapped_assets[:10]:

            print("\n----------------------------------------")

            print(
                f"Asset          : {asset['asset']}"
            )

            print(
                f"Asset Type     : {asset['asset_type']}"
            )

            print(
                f"Business Unit  : {asset['business_unit']}"
            )

            print(
                f"Infrastructure : {asset['infrastructure']}"
            )

            print(
                f"Asset Role     : {asset['asset_role']}"
            )

            print(
                f"Criticality    : {asset['criticality']}"
            )

    else:

        print("\nNo enterprise assets mapped.")

    # ========================================================
    # ENTERPRISE EXPOSURE SUMMARY
    # ========================================================

    print("\n")

    print("=" * 60)

    print("ENTERPRISE EXPOSURE SUMMARY")

    print("=" * 60)

    print(
        f"\nExposure Score : "
        f"{enterprise_exposure['exposure_score']}"
    )

    print(
        f"Exposure Level : "
        f"{enterprise_exposure['exposure_level']}"
    )

    # ========================================================
    # NLP SUMMARY
    # ========================================================

    print("\n")

    print("=" * 60)

    print("NLP THREAT INTELLIGENCE")

    print("=" * 60)

    print("\nTop Threat Terms:\n")

    for term, score in important_terms[:10]:

        print(

            f"- {term:<15}"

            f"TF-IDF Score: "
            f"{round(score, 4)}"
        )

    print("\nThreat Category Distribution:\n")

    for category, entries in nlp_groups.items():

        print(

            f"{category.upper():<15}"
            f": {len(entries)} indicators"
        )

    # ========================================================
    # MITRE SUMMARY
    # ========================================================

    print("\n")

    print("=" * 60)

    print("MITRE ATT&CK SUMMARY")

    print("=" * 60)

    for technique in mitre_summary:

        print(

            f"\n[{technique['id']}] "
            f"{technique['name']}"
        )

    # ========================================================
    # GRAPH VISUALIZATION
    # ========================================================

    print("\n")

    print("=" * 60)

    print("GRAPH VISUALIZATION")

    print("=" * 60)

    print(

        "\nLaunching structured "
        "kill-chain threat graph..."
    )

    visualize_graph(
        threat_graph
    )

    # ========================================================
    # PDF REPORT GENERATION
    # ========================================================

    print("\n")

    print("=" * 60)

    print("PDF REPORT GENERATION")

    print("=" * 60)

    print(
        "\nGenerating intelligence PDF report..."
    )

    report_path = generate_pdf_report(

        {
            "threat_level": threat_level,

            "kill_chain_stages": visible_chain,

            "signals": results,

            "important_terms": important_terms,

            "mitre_matches": mitre_summary,

            "executive_summary": narrative,

            "enriched_iocs": enriched_iocs,

            "impact_analysis": impact_analysis,

            "propagation_summary": propagation_summary,

            "consequence_summary": consequence_summary,

            "business_risk": business_risk,

            "asset_summary": asset_summary,

            "enterprise_exposure":
                enterprise_exposure
        }
    )

    print(
        f"\n✔ PDF Report Generated:"
    )

    print(
        f"  {report_path}"
    )

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    print("\n")

    print("=" * 60)

    print("INTELLIGENCE ANALYSIS COMPLETE")

    print("=" * 60)

    print(
        "\n✔ Threat intelligence processing complete."
    )

    print(
        "✔ NLP intelligence correlation complete."
    )

    print(
        "✔ IOC enrichment complete."
    )

    print(
        "✔ Cross-domain impact analysis complete."
    )

    print(
        "✔ Propagation simulation complete."
    )

    print(
        "✔ Consequence cascade analysis complete."
    )

    print(
        "✔ Enterprise asset mapping complete."
    )

    print(
        "✔ Graph relationship analysis complete."
    )

    print(
        "✔ Threat intelligence report exported."
    )

    print(
        "\nGenerated Output Files:"
    )

    print(
        "- outputs/threat_graph.png"
    )

    print(
        "- outputs/threat_intelligence_report.pdf\n"
    )


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":

    main()