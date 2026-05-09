# """
# Core Threat Intelligence Pipeline
# """

# # ============================================================
# # CRAWLERS
# # ============================================================

# from engine.crawlers.dark_crawler import DarkWebCrawler
# from engine.crawlers.forum_crawler import ForumCrawler
# from engine.crawlers.source_list import DARK_WEB_SOURCES

# # ============================================================
# # EXTRACTORS
# # ============================================================

# from engine.extractors.regex_basics import (
#     extract_basic
# )

# # ============================================================
# # DATASETS
# # ============================================================

# from engine.datasets.dataset_loader import (

#     load_cve_dataset,

#     load_mitre_dataset,

#     load_kev_dataset,

#     load_historical_attacks
# )

# # ============================================================
# # NLP
# # ============================================================

# from engine.nlp.preprocess import (
#     preprocess_text
# )

# from engine.nlp.keyword_analysis import (
#     analyze_keywords
# )

# from engine.nlp.tfidf_analysis import (
#     extract_important_terms
# )

# from engine.nlp.entity_extractor import (
#     extract_entities
# )

# # ============================================================
# # GRAPH
# # ============================================================

# from engine.graph.threat_graph import (
#     build_threat_graph
# )

# # ============================================================
# # MAIN PIPELINE
# # ============================================================

# def run_pipeline():

#     """
#     Executes complete CTI pipeline.
#     """

#     # ========================================================
#     # INITIALIZE CRAWLERS
#     # ========================================================

#     dark = DarkWebCrawler()

#     forum = ForumCrawler()

#     # ========================================================
#     # LOAD DATASETS
#     # ========================================================

#     cve_dataset = load_cve_dataset()

#     mitre_dataset = load_mitre_dataset()

#     kev_dataset = load_kev_dataset()

#     historical_attacks = load_historical_attacks()

#     # ========================================================
#     # STORAGE
#     # ========================================================

#     results = []

#     correlations = []

#     all_documents = []

#     seen = set()

#     print(
#         "\n[+] Starting Threat Intelligence Pipeline...\n"
#     )

#     # ========================================================
#     # CRAWL SOURCES
#     # ========================================================

#     for url in DARK_WEB_SOURCES:

#         print(f"[Crawling] {url}")

#         html = dark.fetch(url)

#         if not html:
#             continue

#         page_data = forum.scrape(

#             html,

#             url
#         )

#         if not page_data:
#             continue

#         page_text = page_data["content"]

#         all_documents.append(page_text)

#         # ====================================================
#         # REGEX EXTRACTION
#         # ====================================================

#         extracted = extract_basic(
#             page_text
#         )

#         # ====================================================
#         # NLP
#         # ====================================================

#         cleaned = preprocess_text(
#             page_text
#         )

#         keyword_analysis = analyze_keywords(
#             cleaned["tokens"]
#         )

#         entities = extract_entities(
#             page_text
#         )

#         # ====================================================
#         # PROCESS KEYWORD SIGNALS
#         # ====================================================

#         keywords = extracted.get(
#             "keywords",
#             {}
#         )

#         for subtype, values in keywords.items():

#             for value in values:

#                 unique_key = (

#                     "keyword",

#                     subtype,

#                     value
#                 )

#                 if unique_key in seen:
#                     continue

#                 seen.add(unique_key)

#                 results.append({

#                     "type": "keyword",

#                     "subtype": subtype,

#                     "value": value,

#                     "source": url,

#                     "source_type": "dark-web"
#                 })

#         # ====================================================
#         # EMAILS
#         # ====================================================

#         for email in extracted.get("emails", []):

#             unique_key = (
#                 "email",
#                 email
#             )

#             if unique_key in seen:
#                 continue

#             seen.add(unique_key)

#             results.append({

#                 "type": "email",

#                 "value": email,

#                 "source": url,

#                 "source_type": "dark-web"
#             })

#         # ====================================================
#         # IPV4
#         # ====================================================

#         for ip in extracted.get("ipv4", []):

#             unique_key = (
#                 "ipv4",
#                 ip
#             )

#             if unique_key in seen:
#                 continue

#             seen.add(unique_key)

#             results.append({

#                 "type": "ipv4",

#                 "value": ip,

#                 "source": url,

#                 "source_type": "dark-web"
#             })

#         # ====================================================
#         # CVE CORRELATION
#         # ====================================================

#         for cve in extracted.get("cves", []):

#             unique_key = (
#                 "cve",
#                 cve
#             )

#             if unique_key in seen:
#                 continue

#             seen.add(unique_key)

#             results.append({

#                 "type": "cve",

#                 "value": cve,

#                 "source": url,

#                 "source_type": "dark-web"
#             })

#             # ------------------------------------------------
#             # CVE DATASET MATCH
#             # ------------------------------------------------

#             for cve_record in cve_dataset:

#                 if (

#                     cve.lower()

#                     ==

#                     cve_record[
#                         "cve_id"
#                     ].lower()
#                 ):

#                     correlations.append({

#                         "type": "cve_correlation",

#                         "cve": cve,

#                         "severity": cve_record[
#                             "severity"
#                         ],

#                         "description": cve_record[
#                             "description"
#                         ]
#                     })

#             # ------------------------------------------------
#             # KEV MATCH
#             # ------------------------------------------------

#             for kev in kev_dataset:

#                 if (

#                     cve.lower()

#                     ==

#                     kev[
#                         "cve_id"
#                     ].lower()
#                 ):

#                     correlations.append({

#                         "type": "kev_correlation",

#                         "cve": cve,

#                         "vendor": kev[
#                             "vendor"
#                         ],

#                         "product": kev[
#                             "product"
#                         ],

#                         "name": kev[
#                             "name"
#                         ]
#                     })

#         # ====================================================
#         # NLP CORRELATIONS
#         # ====================================================

#         for category, terms in keyword_analysis.items():

#             for term, frequency in terms.items():

#                 correlations.append({

#                     "type": "nlp_keyword",

#                     "category": category,

#                     "term": term,

#                     "frequency": frequency
#                 })

#         # ====================================================
#         # ENTITY CORRELATIONS
#         # ====================================================

#         for cve in entities["cves"]:

#             correlations.append({

#                 "type": "nlp_entity",

#                 "entity_type": "cve",

#                 "value": cve
#             })

#         # ====================================================
#         # HISTORICAL ATTACK CORRELATION
#         # ====================================================

#         lower_text = page_text.lower()

#         for attack in historical_attacks:

#             vector = attack[
#                 "vector"
#             ].lower()

#             if vector in lower_text:

#                 correlations.append({

#                     "type": "historical_attack",

#                     "attack_name":
#                         attack["attack_name"],

#                     "vector":
#                         attack["vector"],

#                     "impact":
#                         attack["impact"]
#                 })

#     # ========================================================
#     # TF-IDF ANALYSIS
#     # ========================================================

#     important_terms = extract_important_terms(

#         all_documents,

#         top_n=15
#     )

#     # ========================================================
#     # BUILD GRAPH
#     # ========================================================

#     threat_graph = build_threat_graph(

#         results,

#         correlations
#     )

#     # ========================================================
#     # SUMMARY
#     # ========================================================

#     print(

#         f"\n[+] Total Signals Collected: "
#         f"{len(results)}"
#     )

#     print(

#         f"[+] Correlated Intelligence Matches: "
#         f"{len(correlations)}"
#     )

#     print(

#         f"[+] NLP Important Terms Identified: "
#         f"{len(important_terms)}"
#     )

#     # ========================================================
#     # RETURN
#     # ========================================================

#     return {

#         "signals": results,

#         "correlations": correlations,

#         "important_terms": important_terms,

#         "mitre_dataset": mitre_dataset,

#         "threat_graph": threat_graph
#     }

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

    # ========================================================
    # RETURN
    # ========================================================

    return {

        "signals": results,

        "correlations": correlations,

        "important_terms": important_terms,

        "mitre_dataset": mitre_dataset,

        "threat_graph": threat_graph,

        "enriched_iocs": enriched_iocs
    }