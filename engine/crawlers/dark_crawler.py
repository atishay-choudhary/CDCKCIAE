"""
Dark web crawler.

Supports:
- Tor routing
- Onion sites
- Local mock files
"""

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

        # Mock local files
        if url.startswith("file://"):

            try:

                path = url.replace("file://", "")

                with open(path, "r", encoding="utf-8") as f:
                    return f.read()

            except Exception as e:

                print(f"[Mock File Error] {url} -> {e}")

                return None

        print(f"[Dark Web] Crawling: {url}")

        # Real onion crawling
        return super().fetch(
            url,
            proxies=self.proxies,
            retries=2
        )
