"""
Dark web source registry (FR-1.3).

The built-in list below is the default. To use a broader, documented
list without editing code, create config/dw_sources.json (git-ignored,
so addresses stay out of version control):

    [
      {"name": "...", "url": "http://....onion/", "category": "..."},
      ...
    ]

When that file exists and holds valid entries it replaces the defaults.
Only list sources you are permitted to observe: collection is passive
and read-only, and every access is written to the audit log.
"""

import json
import os


CONFIG_PATH = "config/dw_sources.json"

REQUIRED_KEYS = ("name", "url", "category")


# ============================================================
# DARK WEB SOURCES
# ============================================================

DW_SOURCES = [

    {
        "name": "Breach Forum Mirror",

        "url": "http://uvfeolw6byawkv4fiawpcarpepr3msh3d3a2nbhx6roghpingf7bjhid.onion/",

        "category": "breach_forum"
    },

    {
        "name": "Credential Leak Board",

        "url": "http://6i7tpbu23qnanry473oe4g5ep6zuzxpfj3fzcgraz5sm2zdzkompuvid.onion/",

        "category": "credential_leak"
    },

    {
        "name": "Ransomware Discussion Hub",

        "url": "http://vbdioctupuwnk2n2m37f4pjcdtueyvpgxb65sqirkpl6j7sakyp3c2id.onion/",

        "category": "ransomware"
    }
]


# ============================================================
# GET ALL SOURCES
# ============================================================

def get_all_sources():

    """
    Returns the configured sources: config file if present and valid,
    otherwise the built-in defaults.
    """

    if not os.path.exists(CONFIG_PATH):
        return DW_SOURCES

    try:

        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            configured = json.load(f)

    except (OSError, ValueError) as e:

        print(f"[!] {CONFIG_PATH} unreadable ({e}); using built-in sources.")

        return DW_SOURCES

    valid = [

        source for source in configured

        if isinstance(source, dict)
        and all(source.get(k) for k in REQUIRED_KEYS)
    ] if isinstance(configured, list) else []

    skipped = (len(configured) if isinstance(configured, list) else 0) - len(valid)

    if skipped:

        print(
            f"[!] {CONFIG_PATH}: {skipped} entr"
            f"{'y' if skipped == 1 else 'ies'} skipped "
            f"(need {', '.join(REQUIRED_KEYS)})."
        )

    if not valid:

        print(f"[!] {CONFIG_PATH} has no valid sources; using built-in sources.")

        return DW_SOURCES

    return valid


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