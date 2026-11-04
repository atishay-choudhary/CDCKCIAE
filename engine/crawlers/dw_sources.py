"""
Dark web source registry (FR-1.3).

The registry is the crawl_source table in the database (kind "live").
Add or change sources there (python backend/manage.py shell, or the
dashboard), e.g. one with a search block queried once per keyword:

    name="Ahmia", url="https://ahmia.fi/search/", category="search_engine",
    search={"url": "https://ahmia.fi/search/", "param": "q",
            "form_page": "https://ahmia.fi/"}

Only list sources you are permitted to observe: collection is passive
and read-only, and every access is written to the audit log.
"""

from engine import datastore


# ============================================================
# GET ALL SOURCES
# ============================================================

def get_all_sources():

    """
    Returns the enabled live sources from the database.
    """

    sources = datastore.crawl_sources("live")

    if not sources:
        print(
            "[!] No live sources in the database. Run "
            "python backend/manage.py sync_reference to add the default."
        )

    return sources


# ============================================================
# GET SOURCES BY CATEGORY
# ============================================================

def get_sources_by_category(category):

    """
    Returns sources matching a category.
    """

    return [

        source

        for source in get_all_sources()

        if source["category"] == category
    ]
