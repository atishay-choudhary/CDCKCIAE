"""
Dark web source registry.

Stores:
- onion/forum sources
- source metadata
- intelligence categories
"""

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
# GET SOURCES BY CATEGORY
# ============================================================

def get_sources_by_category(category):

    """
    Returns sources matching a category.
    """

    return [

        source

        for source in DW_SOURCES

        if source["category"] == category
    ]


# ============================================================
# GET ALL SOURCES
# ============================================================

def get_all_sources():

    """
    Returns all configured sources.
    """

    return DW_SOURCES