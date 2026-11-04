"""
Mock intelligence sources (local test pages kept in the database,
table crawl_source with kind "mock").
"""

from engine import datastore


def dark_web_sources():

    """
    URLs of the mock pages (mock://forum1.html, ...).
    """

    return [source["url"] for source in datastore.crawl_sources("mock")]
