"""
Live dark web crawler.

Responsible for:
- Tor-based crawling
- keyword-driven intelligence collection
- raw content extraction
"""

from bs4 import BeautifulSoup

from engine.crawlers.tor_session import (
    create_tor_session
)

from engine.crawlers.dw_sources import (
    get_all_sources
)


# ============================================================
# DARK WEB LIVE CRAWLER
# ============================================================

class DarkWebLiveCrawler:

    def __init__(self):

        self.session = create_tor_session()

        self.sources = get_all_sources()


    # ========================================================
    # FETCH PAGE
    # ========================================================

    def fetch_page(self, url):

        """
        Fetches HTML content through Tor.
        """

        try:

            response = self.session.get(

                url,

                timeout=60
            )

            if response.status_code == 200:

                return response.text

            return None

        except Exception as e:

            print(f"[FETCH ERROR] {url}")

            print(str(e))

            return None


    # ========================================================
    # EXTRACT TEXT
    # ========================================================

    def extract_text(self, html):

        """
        Extracts visible text from HTML.
        """

        try:

            soup = BeautifulSoup(

                html,

                "html.parser"
            )

            return soup.get_text(

                separator=" ",

                strip=True
            )

        except Exception:

            return ""


    # ========================================================
    # KEYWORD MATCH
    # ========================================================

    def keyword_match(

        self,

        text,

        keywords
    ):

        """
        Checks whether text contains keywords.
        """

        matches = []

        text_lower = text.lower()

        for keyword in keywords:

            if keyword.lower() in text_lower:

                matches.append(keyword)

        return matches


    # ========================================================
    # SEARCH SOURCES
    # ========================================================

    def search_sources(

        self,

        keywords
    ):

        """
        Searches all configured sources for keywords.
        """

        collected_data = []

        print("\n[DARK WEB LIVE SEARCH]\n")

        for source in self.sources:

            print(f"[SOURCE] {source['name']}")

            print(f"[URL] {source['url']}")

            html = self.fetch_page(

                source["url"]
            )

            if not html:

                print("[STATUS] Failed\n")

                continue

            text = self.extract_text(

                html
            )

            matches = self.keyword_match(

                text,

                keywords
            )

            if matches:

                print(

                    f"[MATCHES] "
                    f"{', '.join(matches)}"
                )

                collected_data.append({

                    "source": source["name"],

                    "url": source["url"],

                    "category": source["category"],

                    "matches": matches,

                    "content": text[:5000]
                })

            else:

                print("[MATCHES] None")

            print()

        return collected_data