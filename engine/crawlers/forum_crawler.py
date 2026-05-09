"""
Forum crawler.

Responsible for:
- cleaning HTML
- extracting readable text
"""

from bs4 import BeautifulSoup
from datetime import datetime
from .base import BaseCrawler


class ForumCrawler(BaseCrawler):

    def clean_content(self, html):

        """
        Removes unwanted HTML elements.
        """

        soup = BeautifulSoup(html, "html.parser")

        # Remove noisy elements
        for tag in soup([
            "script",
            "style",
            "nav",
            "footer",
            "header",
            "aside"
        ]):
            tag.decompose()

        text = soup.get_text(separator=" ")

        # Normalize spaces
        text = " ".join(text.split())

        if len(text) < 30:
            return None

        return text

    def scrape(self, html, source_url):

        """
        Converts raw HTML into cleaned content.
        """

        cleaned_text = self.clean_content(html)

        if not cleaned_text:
            return None

        return {
            "url": source_url,
            "content": cleaned_text,
            "scraped_at": datetime.utcnow().isoformat()
        }