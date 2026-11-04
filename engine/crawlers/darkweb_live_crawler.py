"""
Live dark web crawler (FR-1.2, FR-1.4, FR-1.5).

Responsible for:
- Tor-based, read-only collection (HTTP GET only)
- retry with exponential backoff and jitter; Retry-After is honoured
- one failing source never stops the run
- an audit record (database table audit_event) for every source accessed

Policy: the crawler does not try to defeat anti-crawling defences.
Rate limiting (429 / 503) is waited out; a 403 or any other client
error is recorded and the source is skipped. Responses are size-capped
and non-text content is not stored.
"""

import random
import time
from urllib.parse import quote_plus
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup

from engine.crawlers.tor_session import (
    create_tor_session
)

from engine import datastore

from engine.crawlers.dw_sources import (
    get_all_sources
)


MAX_ATTEMPTS = 4
BACKOFF_BASE = 2.0
BACKOFF_CAP = 60.0
REQUEST_TIMEOUT = (30, 60)
MAX_BYTES = 2_000_000
SOURCE_DELAY = (2.0, 5.0)

RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}


# ============================================================
# AUDIT LOG (FR-1.5)
# ============================================================

def log_event(event):

    """
    Stores one audit record in the database. Never raises: auditing
    must not be the reason a crawl fails.
    """

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **event
    }

    try:

        datastore.log_event(event)

    except Exception as e:

        print(f"[!] Audit event not stored: {e}")


def _retry_after(value):

    try:
        return max(0.0, float(value))

    except (TypeError, ValueError):
        return None


# ============================================================
# DARK WEB LIVE CRAWLER
# ============================================================

class DarkWebLiveCrawler:

    def __init__(self):

        self.session = create_tor_session()

        self.sources = get_all_sources()

        self.report = {
            "attempted": 0,
            "reached": 0,
            "failed": 0,
            "matched": 0
        }


    # ========================================================
    # FETCH PAGE
    # ========================================================

    def fetch_page(self, url, params=None):

        """
        GETs a page through Tor with retry and backoff.

        Returns {"html", "http_status", "attempts", "bytes", "error"};
        html is None when the page could not be collected.
        """

        outcome = {
            "html": None,
            "http_status": None,
            "attempts": 0,
            "bytes": 0,
            "error": None
        }

        for attempt in range(1, MAX_ATTEMPTS + 1):

            outcome["attempts"] = attempt

            wait = None

            try:

                with self.session.get(

                    url,

                    params=params,

                    timeout=REQUEST_TIMEOUT,

                    stream=True

                ) as response:

                    outcome["http_status"] = response.status_code

                    if response.status_code == 200:

                        kind = response.headers.get("Content-Type", "")

                        if kind and "text" not in kind and "html" not in kind:

                            outcome["error"] = f"non-text content skipped ({kind})"

                            return outcome

                        chunks, size = [], 0

                        for chunk in response.iter_content(65536):

                            chunks.append(chunk)

                            size += len(chunk)

                            if size >= MAX_BYTES:
                                break

                        outcome["html"] = b"".join(chunks).decode(
                            response.encoding or "utf-8",
                            errors="replace"
                        )

                        outcome["bytes"] = size

                        outcome["error"] = None

                        return outcome

                    outcome["error"] = f"HTTP {response.status_code}"

                    if response.status_code not in RETRY_STATUS:

                        outcome["error"] += " (not retried)"

                        return outcome

                    wait = _retry_after(response.headers.get("Retry-After"))

            except requests.RequestException as e:

                outcome["error"] = type(e).__name__

            if attempt < MAX_ATTEMPTS:

                delay = min(

                    BACKOFF_CAP,

                    wait if wait is not None
                    else BACKOFF_BASE ** attempt + random.uniform(0, 1)
                )

                print(
                    f"[RETRY] attempt {attempt}/{MAX_ATTEMPTS} failed "
                    f"({outcome['error']}); waiting {delay:.0f}s"
                )

                time.sleep(delay)

        return outcome


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

    def search_targets(self, source, keywords):

        """
        Pages to fetch for one source: [(shown_url, fetch_url, params,
        keyword)].

        A source with a "search" block is queried once per keyword:

            "search": {"url": "https://host/search/", "param": "q",
                       "form_page": "https://host/"}

        form_page (optional) is fetched first and the hidden fields of
        its search form (anti-bot tokens that change over time) are sent
        with the query, as a browser would. Without "search" the fixed
        url is fetched once and filtered by keyword.
        """

        search = source.get("search")

        if not isinstance(search, dict) or not search.get("url"):
            return [(source["url"], source["url"], None, None)]

        hidden = {}

        if search.get("form_page"):

            page = self.fetch_page(search["form_page"])

            if page["html"]:

                form = BeautifulSoup(page["html"], "html.parser").find("form")

                for field in (form.find_all("input", type="hidden")
                              if form else []):

                    if field.get("name"):
                        hidden[field["name"]] = field.get("value", "")

        param = search.get("param", "q")

        return [
            (
                f"{search['url']}?{param}={quote_plus(keyword)}",
                search["url"],
                {param: keyword, **hidden},
                keyword
            )
            for keyword in keywords
        ]


    def search_sources(

        self,

        keywords
    ):

        """
        Searches all configured sources for keywords. Every page is
        audit-logged; a failing page is skipped, never fatal.
        """

        collected_data = []

        print("\n[DARK WEB LIVE SEARCH]\n")

        first = True

        for source in self.sources:

            for shown, url, params, keyword in self.search_targets(

                source,

                keywords
            ):

                if not first:
                    time.sleep(random.uniform(*SOURCE_DELAY))

                first = False

                print(f"[SOURCE] {source['name']}")

                print(f"[URL] {shown}")

                self.report["attempted"] += 1

                outcome = self.fetch_page(url, params)

                audit = {

                    "mode": "live",

                    "source": source["name"],

                    "url": shown,

                    "category": source["category"],

                    "keywords": keywords,

                    "keyword": keyword,

                    "http_status": outcome["http_status"],

                    "attempts": outcome["attempts"],

                    "bytes": outcome["bytes"],

                    "error": outcome["error"]
                }

                if outcome["html"] is None:

                    self.report["failed"] += 1

                    print(f"[STATUS] Failed ({outcome['error']})\n")

                    log_event({**audit, "status": "failed"})

                    continue

                self.report["reached"] += 1

                text = self.extract_text(outcome["html"])

                matches = self.keyword_match(text, [keyword] if keyword else keywords)

                if matches:

                    self.report["matched"] += 1

                    print(f"[MATCHES] {', '.join(matches)}")

                    log_event({**audit, "status": "collected", "matches": matches})

                    collected_data.append({

                        "source": source["name"],

                        "url": shown,

                        "category": source["category"],

                        "matches": matches,

                        "content": text[:5000]
                    })

                else:

                    print("[MATCHES] None")

                    log_event({**audit, "status": "no_match"})

                print()

        return collected_data
