"""
Threat graph builder.

Creates relationships between:
- kill chain stages
- extracted indicators
- intelligence artifacts
"""

import networkx as nx


# ============================================================
# CATEGORY → STAGE MAPPING
# ============================================================

CATEGORY_STAGE_MAP = {

    "access": "access",

    "exploit": "exploit",

    "movement": "movement",

    "leak": "leak",

    "sale": "sale"
}


# ============================================================
# STAGE CONNECTION FLOW
# ============================================================

STAGE_FLOW = [

    ("access", "exploit"),

    ("exploit", "movement"),

    ("movement", "leak"),

    ("leak", "sale")
]


# ============================================================
# BUILD THREAT GRAPH
# ============================================================

def build_threat_graph(

    results,

    correlations
):

    """
    Builds structured CTI graph.
    """

    graph = nx.DiGraph()

    # ========================================================
    # ADD STAGE NODES
    # ========================================================

    for stage in CATEGORY_STAGE_MAP.values():

        graph.add_node(stage)

    # ========================================================
    # CONNECT STAGES
    # ========================================================

    for source, target in STAGE_FLOW:

        graph.add_edge(

            source,

            target
        )

    # ========================================================
    # ADD ARTIFACTS
    # ========================================================

    for item in results:

        # ----------------------------------------------------
        # KEYWORD NODES
        # ----------------------------------------------------

        if item["type"] == "keyword":

            category = item["subtype"]

            value = item["value"]

            if category in CATEGORY_STAGE_MAP:

                stage = CATEGORY_STAGE_MAP[category]

                graph.add_node(value)

                graph.add_edge(

                    stage,

                    value
                )

        # ----------------------------------------------------
        # EMAILS
        # ----------------------------------------------------

        elif item["type"] == "email":

            graph.add_node(item["value"])

            graph.add_edge(

                "access",

                item["value"]
            )

        # ----------------------------------------------------
        # IPV4
        # ----------------------------------------------------

        elif item["type"] == "ipv4":

            graph.add_node(item["value"])

            graph.add_edge(

                "movement",

                item["value"]
            )

        # ----------------------------------------------------
        # CREDS
        # ----------------------------------------------------

        elif item["type"] == "creds":

            graph.add_node(item["value"])

            graph.add_edge(

                "access",

                item["value"]
            )

    return graph