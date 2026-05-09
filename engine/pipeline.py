"""
Core intelligence pipeline.
"""

from engine.crawlers.dark_crawler import DarkWebCrawler
from engine.crawlers.forum_crawler import ForumCrawler
from engine.crawlers.source_list import DARK_WEB_SOURCES

from engine.extractors.regex_basics import extract_basic


def run_pipeline():

    # Initialize crawlers
    dark = DarkWebCrawler()

    forum = ForumCrawler()

    # Final intelligence results
    results = []

    # Used for global deduplication
    seen = set()

    print("\n[+] Starting Threat Intelligence Pipeline...\n")

    # =========================================================
    # STEP 1 — Crawl Dark Web Sources
    # =========================================================

    for url in DARK_WEB_SOURCES:

        print(f"[Crawling] {url}")

        # Fetch raw HTML/content
        html = dark.fetch(url)

        if not html:

            print(f"[!] Failed to fetch: {url}")

            continue

        # Convert HTML -> clean text
        page_data = forum.scrape(html, url)

        if not page_data:

            print(f"[!] Failed to clean content: {url}")

            continue

        # Extract threat artifacts/signals
        extracted = extract_basic(page_data["content"])

        # =====================================================
        # STEP 2 — Process Extracted Data
        # =====================================================

        for key, values in extracted.items():

            # -------------------------------------------------
            # Handle keyword intelligence separately
            # -------------------------------------------------

            if key == "keywords":

                for subtype, keyword_values in values.items():

                    for value in keyword_values:

                        # Global deduplication
                        entry = ("keyword", subtype, value)

                        if entry in seen:
                            continue

                        seen.add(entry)

                        results.append({

                            "type": "keyword",

                            "subtype": subtype,

                            "value": value,

                            "source": url,

                            "source_type": "dark-web"
                        })

                continue

            # -------------------------------------------------
            # Handle normal artifacts
            # -------------------------------------------------

            for value in values:

                # Convert plural artifact names -> singular
                clean_key = key.rstrip("s")

                # Deduplicate globally
                entry = (clean_key, value)

                if entry in seen:
                    continue

                seen.add(entry)

                results.append({

                    "type": clean_key,

                    "value": value,

                    "source": url,

                    "source_type": "dark-web"
                })

    # =========================================================
    # FINAL SUMMARY
    # =========================================================

    print(f"\n[+] Total Signals Collected: {len(results)}")

    return results