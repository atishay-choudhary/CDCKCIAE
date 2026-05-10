"""
Core Threat Intelligence Pipeline
"""

# ============================================================
# CRAWLERS
# ============================================================

from engine.crawlers.dark_crawler import DarkWebCrawler
from engine.crawlers.forum_crawler import ForumCrawler
from engine.crawlers.source_list import DARK_WEB_SOURCES

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
# MAIN PIPELINE
# ============================================================

def run_pipeline():

    """
    Executes complete CTI pipeline.
    """

    # ========================================================
    # INITIALIZE CRAWLERS
    # ========================================================

    dark = DarkWebCrawler()

    forum = ForumCrawler()

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
        "\n[+] Starting Threat Intelligence Pipeline...\n"
    )

    # ========================================================
    # CRAWL SOURCES
    # ========================================================

    for url in DARK_WEB_SOURCES:

        print(f"[Crawling] {url}")

        html = dark.fetch(url)

        if not html:
            continue

        page_data = forum.scrape(

            html,

            url
        )

        if not page_data:
            continue

        page_text = page_data["content"]

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
        # PROCESS KEYWORD SIGNALS
        # ====================================================

        keywords = extracted.get(
            "keywords",
            {}
        )

        for subtype, values in keywords.items():

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

                    "source": url,

                    "source_type": "dark-web"
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

                "source": url,

                "source_type": "dark-web"
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

                "source": url,

                "source_type": "dark-web"
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

                "source": url,

                "source_type": "dark-web"
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
    # CROSS-DOMAIN IMPACT ENGINE
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
    # ASSET MAPPING ENGINE
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
    # BUILD GRAPH
    # ========================================================

    threat_graph = build_threat_graph(

        results,

        correlations
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