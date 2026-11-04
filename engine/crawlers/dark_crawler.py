"""
Dark web crawler.

Supports:
- Tor routing
- Onion sites
- Local mock files
"""

from engine import datastore

from .base import BaseCrawler


class DarkWebCrawler(BaseCrawler):

    def __init__(self):

        super().__init__()

        # Tor SOCKS proxy
        self.proxies = {
            "http": "socks5h://127.0.0.1:9150",
            "https": "socks5h://127.0.0.1:9150"
        }

    def fetch(self, url):

        """
        Fetch dark web content.
        """

        # Mock pages (stored in the database)
        if url.startswith("mock://"):

            page = datastore.mock_page(url)

            if page is None:
                print(f"[Mock Page Error] {url} not found in the database")

            return page

        print(f"[Dark Web] Crawling: {url}")

        # Real onion crawling
        return super().fetch(
            url,
            proxies=self.proxies,
            retries=2
        )
