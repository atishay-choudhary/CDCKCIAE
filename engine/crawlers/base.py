"""
Base crawler module.

Handles:
- HTTP requests
- retries
- timeouts
- generic fetch logic
"""

import requests
import time


class BaseCrawler:

    def __init__(self):

        # Generic browser-like user agent
        self.headers = {
            "User-Agent": "Mozilla/5.0"
        }

    def fetch(self, url, proxies=None, retries=2):

        """
        Fetches content from a URL with retry handling.
        """

        for attempt in range(retries + 1):

            try:

                response = requests.get(
                    url,
                    headers=self.headers,
                    proxies=proxies,
                    timeout=20
                )

                response.raise_for_status()

                return response.text

            except Exception as e:

                print(
                    f"[Fetch Error] {url} "
                    f"(Attempt {attempt + 1}) -> {e}"
                )

                time.sleep(1)

        return None