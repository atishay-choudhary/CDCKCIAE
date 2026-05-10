"""
Live dark web intelligence pipeline.

Responsible for:
- keyword-driven dark web acquisition
- live intelligence processing
- downstream CTI analysis
"""

import os

# ============================================================
# LIVE CRAWLER
# ============================================================

from engine.crawlers.darkweb_live_crawler import (
    DarkWebLiveCrawler
)

# ============================================================
# EXTRACTORS
# ============================================================

from engine.extractors.regex_basics import (
    extract_basic
)

# ============================================================
# DATASETS
# ============================================================

from engine.datasets.dataset_loader import (

    load_cve_dataset,

    load_mitre_dataset,

    load_kev_dataset,

    load_historical_attacks
)

# ============================================================
# NLP
# ============================================================

from engine.nlp.preprocess import (
    preprocess_text
)

from engine.nlp.keyword_analysis import (
    analyze_keywords
)

from engine.nlp.tfidf_analysis import (
    extract_important_terms
)

from engine.nlp.entity_extractor import (
    extract_entities
)

# ============================================================
# GRAPH
# ============================================================

from engine.graph.threat_graph import (
    build_threat_graph
)

from engine.graph.graph_visualizer import (
    visualize_graph

)

# ============================================================
# INTELLIGENCE
# ============================================================

from engine.intelligence.ioc_enrichment import (
    enrich_iocs
)

from engine.intelligence.killchain_mapper import (
    map_kill_chain
)

from engine.intelligence.threat_scorer import (
    calculate_threat_score
)

from engine.intelligence.impact_engine import (
    analyze_cross_domain_impact
)

# ============================================================
# PROPAGATION ENGINE
# ============================================================

from engine.intelligence.propagation_engine import (

    generate_propagation_model,

    summarize_propagation
)

# ============================================================
# CONSEQUENCE ENGINE
# ============================================================

from engine.intelligence.consequence_engine import (

    generate_consequence_model,

    summarize_consequences,

    calculate_business_risk
)

# ============================================================
# ASSET MAPPING ENGINE
# ============================================================

from engine.intelligence.asset_mapper import (

    map_assets,

    summarize_assets,

    calculate_enterprise_exposure
)


# ============================================================
# RUN LIVE PIPELINE
# ============================================================

def run_darkweb_pipeline(keywords):

    """
    Executes live dark web CTI pipeline.
    """

    # ========================================================
    # CREATE OUTPUT DIRECTORIES
    # ========================================================

    os.makedirs(
        "outputs/darkweb",
        exist_ok=True
    )

    # ========================================================
    # INITIALIZE CRAWLER
    # ========================================================

    crawler = DarkWebLiveCrawler()

    # ========================================================
    # LOAD DATASETS
    # ========================================================

    cve_dataset = load_cve_dataset()

    mitre_dataset = load_mitre_dataset()

    kev_dataset = load_kev_dataset()

    historical_attacks = load_historical_attacks()

    # ========================================================
    # STORAGE
    # ========================================================

    results = []

    correlations = []

    all_documents = []

    seen = set()

    print(
        "\n[+] Starting Live Dark Web Pipeline...\n"
    )

    # ========================================================
    # LIVE COLLECTION
    # ========================================================

    collected_data = crawler.search_sources(
        keywords
    )

    # ========================================================
    # PROCESS COLLECTED DATA
    # ========================================================

    for item in collected_data:

        page_text = item["content"]

        source_url = item["url"]

        all_documents.append(page_text)

        # ====================================================
        # REGEX EXTRACTION
        # ====================================================

        extracted = extract_basic(
            page_text
        )

        # ====================================================
        # NLP
        # ====================================================

        cleaned = preprocess_text(
            page_text
        )

        keyword_analysis = analyze_keywords(
            cleaned["tokens"]
        )

        entities = extract_entities(
            page_text
        )

        # ====================================================
        # KEYWORD SIGNALS
        # ====================================================

        keywords_found = extracted.get(
            "keywords",
            {}
        )

        for subtype, values in keywords_found.items():

            for value in values:

                unique_key = (

                    "keyword",

                    subtype,

                    value
                )

                if unique_key in seen:
                    continue

                seen.add(unique_key)

                results.append({

                    "type": "keyword",

                    "subtype": subtype,

                    "value": value,

                    "source": source_url,

                    "source_type": "live-darkweb"
                })

        # ====================================================
        # EMAILS
        # ====================================================

        for email in extracted.get("emails", []):

            unique_key = (
                "email",
                email
            )

            if unique_key in seen:
                continue

            seen.add(unique_key)

            results.append({

                "type": "email",

                "value": email,

                "source": source_url,

                "source_type": "live-darkweb"
            })

        # ====================================================
        # IPV4
        # ====================================================

        for ip in extracted.get("ipv4", []):

            unique_key = (
                "ipv4",
                ip
            )

            if unique_key in seen:
                continue

            seen.add(unique_key)

            results.append({

                "type": "ipv4",

                "value": ip,

                "source": source_url,

                "source_type": "live-darkweb"
            })

        # ====================================================
        # CVE CORRELATION
        # ====================================================

        for cve in extracted.get("cves", []):

            unique_key = (
                "cve",
                cve
            )

            if unique_key in seen:
                continue

            seen.add(unique_key)

            results.append({

                "type": "cve",

                "value": cve,

                "source": source_url,

                "source_type": "live-darkweb"
            })

            # ------------------------------------------------
            # CVE DATASET MATCH
            # ------------------------------------------------

            for cve_record in cve_dataset:

                if (

                    cve.lower()

                    ==

                    cve_record[
                        "cve_id"
                    ].lower()
                ):

                    correlations.append({

                        "type": "cve_correlation",

                        "cve": cve,

                        "severity": cve_record.get(
                            "severity",
                            "UNKNOWN"
                        ),

                        "description": cve_record.get(
                            "description",
                            "No description"
                        )
                    })

            # ------------------------------------------------
            # KEV MATCH
            # ------------------------------------------------

            for kev in kev_dataset:

                if (

                    cve.lower()

                    ==

                    kev[
                        "cve_id"
                    ].lower()
                ):

                    correlations.append({

                        "type": "kev_correlation",

                        "cve": cve,

                        "vendor": kev.get(
                            "vendor",
                            "UNKNOWN"
                        ),

                        "product": kev.get(
                            "product",
                            "UNKNOWN"
                        ),

                        "name": kev.get(
                            "name",
                            "UNKNOWN"
                        )
                    })

        # ====================================================
        # NLP CORRELATIONS
        # ====================================================

        for category, terms in keyword_analysis.items():

            for term, frequency in terms.items():

                correlations.append({

                    "type": "nlp_keyword",

                    "category": category,

                    "term": term,

                    "frequency": frequency
                })

        # ====================================================
        # ENTITY CORRELATIONS
        # ====================================================

        for cve in entities.get("cves", []):

            correlations.append({

                "type": "nlp_entity",

                "entity_type": "cve",

                "value": cve
            })

        # ====================================================
        # HISTORICAL ATTACK CORRELATION
        # ====================================================

        lower_text = page_text.lower()

        for attack in historical_attacks:

            vector = attack[
                "vector"
            ].lower()

            if vector in lower_text:

                correlations.append({

                    "type": "historical_attack",

                    "attack_name":
                        attack["attack_name"],

                    "vector":
                        attack["vector"],

                    "impact":
                        attack["impact"]
                })

    # ========================================================
    # TF-IDF ANALYSIS
    # ========================================================

    important_terms = extract_important_terms(

        all_documents,

        top_n=15
    )

    # ========================================================
    # IOC ENRICHMENT
    # ========================================================

    enriched_iocs = enrich_iocs(

        results,

        correlations
    )

    # ========================================================
    # KILL CHAIN MAPPING
    # ========================================================

    kill_chain = map_kill_chain(
        results
    )

    # ========================================================
    # THREAT SCORING
    # ========================================================

    threat_level = calculate_threat_score(

        results,

        correlations
    )

    # ========================================================
    # IMPACT ANALYSIS
    # ========================================================

    impact_analysis = analyze_cross_domain_impact(

        results=results,

        kill_chain=kill_chain,

        threat_level=threat_level,

        ioc_enrichment=enriched_iocs
    )

    # ========================================================
    # PROPAGATION ENGINE
    # ========================================================

    propagation_results = generate_propagation_model(

        kill_chain
    )

    propagation_summary = summarize_propagation(

        propagation_results
    )

    # ========================================================
    # CONSEQUENCE ENGINE
    # ========================================================

    consequence_results = generate_consequence_model(

        propagation_results
    )

    consequence_summary = summarize_consequences(

        consequence_results
    )

    business_risk = calculate_business_risk(

        consequence_results
    )

    # ========================================================
    # ASSET MAPPING
    # ========================================================

    mapped_assets = map_assets(

        results,

        enriched_iocs
    )

    asset_summary = summarize_assets(

        mapped_assets
    )

    enterprise_exposure = calculate_enterprise_exposure(

        mapped_assets
    )

    # ========================================================
    # GRAPH
    # ========================================================

    threat_graph = build_threat_graph(

        results,

        correlations
    )

    # ========================================================
    # SAVE DARK WEB GRAPH
    # ========================================================

    visualize_graph(

        threat_graph,
    )

       # ========================================================
    # SUMMARY
    # ========================================================

    print(

        f"\n[+] Total Signals Collected: "
        f"{len(results)}"
    )

    print(

        f"[+] Correlated Intelligence Matches: "
        f"{len(correlations)}"
    )

    print(

        f"[+] NLP Important Terms Identified: "
        f"{len(important_terms)}"
    )

    print(

        f"[+] IOC Enrichment Records Generated: "
        f"{len(enriched_iocs)}"
    )

    print(

        f"[+] Cross-Domain Impact Score: "
        f"{impact_analysis['impact_score']}"
    )

    print(

        f"[+] Propagation Paths Generated: "
        f"{len(propagation_results)}"
    )

    print(

        f"[+] Consequence Events Generated: "
        f"{len(consequence_results)}"
    )

    print(

        f"[+] Enterprise Assets Mapped: "
        f"{len(mapped_assets)}"
    )

    # ========================================================
    # DETAILED OUTPUT
    # ========================================================

    print("\n" + "=" * 70)
    print("LIVE DARK WEB INTELLIGENCE ANALYSIS")
    print("=" * 70)

    # ========================================================
    # SIGNALS
    # ========================================================

    print("\n[SIGNALS COLLECTED]\n")

    for signal in results:

        print(signal)

    # ========================================================
    # CORRELATIONS
    # ========================================================

    print("\n[CORRELATED INTELLIGENCE]\n")

    for correlation in correlations:

        print(correlation)

    # ========================================================
    # NLP TERMS
    # ========================================================

    print("\n[NLP IMPORTANT TERMS]\n")

    for term in important_terms:

        print(term)

    # ========================================================
    # IOC ENRICHMENT
    # ========================================================

    print("\n[IOC ENRICHMENT]\n")

    for ioc in enriched_iocs:

        print(ioc)

    # ========================================================
    # KILL CHAIN
    # ========================================================

    print("\n[KILL CHAIN ANALYSIS]\n")

    print(
        " → ".join(kill_chain)
    )

    # ========================================================
    # THREAT LEVEL
    # ========================================================

    print("\n[THREAT LEVEL]\n")

    print(threat_level)

    # ========================================================
    # IMPACT ANALYSIS
    # ========================================================

    print("\n[CROSS-DOMAIN IMPACT ANALYSIS]\n")

    for key, value in impact_analysis.items():

        print(f"{key}: {value}")

    # ========================================================
    # PROPAGATION RESULTS
    # ========================================================

    print("\n[PROPAGATION ENGINE RESULTS]\n")

    for propagation in propagation_results:

        print(propagation)

    # ========================================================
    # PROPAGATION SUMMARY
    # ========================================================

    print("\n[PROPAGATION SUMMARY]\n")

    print(propagation_summary)

    # ========================================================
    # CONSEQUENCE RESULTS
    # ========================================================

    print("\n[CONSEQUENCE ENGINE RESULTS]\n")

    for consequence in consequence_results:

        print(consequence)

    # ========================================================
    # CONSEQUENCE SUMMARY
    # ========================================================

    print("\n[CONSEQUENCE SUMMARY]\n")

    print(consequence_summary)

    # ========================================================
    # BUSINESS RISK
    # ========================================================

    print("\n[BUSINESS RISK ASSESSMENT]\n")

    print(business_risk)

    # ========================================================
    # ASSET MAPPING
    # ========================================================

    print("\n[ENTERPRISE ASSET MAPPING]\n")

    for asset in mapped_assets:

        print(asset)

    # ========================================================
    # ASSET SUMMARY
    # ========================================================

    print("\n[ASSET SUMMARY]\n")

    print(asset_summary)

    # ========================================================
    # ENTERPRISE EXPOSURE
    # ========================================================

    print("\n[ENTERPRISE EXPOSURE ANALYSIS]\n")

    print(enterprise_exposure)

    print("\n" + "=" * 70)
    print("LIVE CTI EXECUTION COMPLETED")
    print("=" * 70)

    # ========================================================
    # RETURN
    # ========================================================

    return {

        "signals": results,

        "correlations": correlations,

        "important_terms": important_terms,

        "mitre_dataset": mitre_dataset,

        "threat_graph": threat_graph,

        "enriched_iocs": enriched_iocs,

        "kill_chain": kill_chain,

        "threat_level": threat_level,

        "impact_analysis": impact_analysis,

        "propagation_results": propagation_results,

        "propagation_summary": propagation_summary,

        "consequence_results": consequence_results,

        "consequence_summary": consequence_summary,

        "business_risk": business_risk,

        "mapped_assets": mapped_assets,

        "asset_summary": asset_summary,

        "enterprise_exposure": enterprise_exposure
    }