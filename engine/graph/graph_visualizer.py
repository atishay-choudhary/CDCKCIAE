"""
Structured CTI graph visualization.

Creates a kill-chain-oriented
threat intelligence graph.
"""

import os

from datetime import datetime

import matplotlib.pyplot as plt
import networkx as nx


# ============================================================
# KILL CHAIN ORDER
# ============================================================

KILL_CHAIN_ORDER = {

    "access": 0,

    "exploit": 1,

    "movement": 2,

    "leak": 3,

    "sale": 4
}


# ============================================================
# DISPLAY LABELS
# ============================================================

STAGE_LABELS = {

    "access": "INITIAL ACCESS",

    "exploit": "EXECUTION",

    "movement": "PRIVILEGE ESCALATION",

    "leak": "EXFILTRATION",

    "sale": "MONETIZATION"
}


# ============================================================
# COLORS
# ============================================================

CATEGORY_COLORS = {

    "access": "#00BCD4",

    "exploit": "#FF7043",

    "movement": "#AB47BC",

    "leak": "#EF5350",

    "sale": "#66BB6A",

    "artifact": "#90CAF9",

    "support": "#546E7A"
}


# ============================================================
# SUPPORTING INFRA KEYWORDS
# ============================================================

SUPPORTING_KEYWORDS = [

    "@",

    ".com",

    "185.",

    "creds",

    "records"
]


# ============================================================
# BUILD POSITIONS
# ============================================================

def build_positions(graph):

    """
    Creates structured kill-chain layout.
    """

    positions = {}

    grouped_nodes = {}

    stage_spacing_x = 10

    child_spacing_y = 2.8

    # --------------------------------------------------------
    # INITIALIZE GROUPS
    # --------------------------------------------------------

    for stage in KILL_CHAIN_ORDER:

        grouped_nodes[stage] = []

    # --------------------------------------------------------
    # GROUP CHILD NODES
    # --------------------------------------------------------

    for source, target in graph.edges():

        if source in KILL_CHAIN_ORDER:

            grouped_nodes[source].append(target)

    # --------------------------------------------------------
    # POSITION STAGES + CHILDREN
    # --------------------------------------------------------

    for stage, index in KILL_CHAIN_ORDER.items():

        x = index * stage_spacing_x

        y = 0

        positions[stage] = (x, y)

        children = grouped_nodes[stage]

        start_y = -3

        visible_index = 0

        for child in children:

            # ------------------------------------------------
            # SKIP SUPPORT INFRA
            # ------------------------------------------------

            is_support = False

            for keyword in SUPPORTING_KEYWORDS:

                if keyword.lower() in str(child).lower():

                    is_support = True

                    break

            if is_support:
                continue

            child_y = start_y - (

                visible_index * child_spacing_y
            )

            positions[child] = (

                x,

                child_y
            )

            visible_index += 1

    return positions


# ============================================================
# NODE SIZE LOGIC
# ============================================================

def get_node_size(node):

    """
    Dynamic node sizing
    based on threat relevance.
    """

    high_priority = [

        "rce",

        "exploit",

        "leak",

        "dataset",

        "archive",

        "ssn"
    ]

    medium_priority = [

        "entry",

        "foothold",

        "internal",

        "escalate"
    ]

    node_text = str(node).lower()

    for keyword in high_priority:

        if keyword in node_text:

            return 3600

    for keyword in medium_priority:

        if keyword in node_text:

            return 3000

    return 2600


# ============================================================
# VISUALIZE GRAPH
# ============================================================

def visualize_graph(graph):

    """
    Displays structured CTI graph.
    """

    plt.figure(figsize=(28, 15))

    # --------------------------------------------------------
    # BACKGROUND
    # --------------------------------------------------------

    plt.gcf().set_facecolor("#F4F6F8")

    # --------------------------------------------------------
    # POSITIONS
    # --------------------------------------------------------

    pos = build_positions(graph)

    # --------------------------------------------------------
    # STAGE NODES
    # --------------------------------------------------------

    stage_nodes = [

        node for node in graph.nodes()

        if node in KILL_CHAIN_ORDER
    ]

    stage_colors = [

        CATEGORY_COLORS[node]

        for node in stage_nodes
    ]

    nx.draw_networkx_nodes(

        graph,

        pos,

        nodelist=stage_nodes,

        node_color=stage_colors,

        node_size=6200,

        alpha=0.95
    )

    # --------------------------------------------------------
    # SPLIT SUPPORT + ARTIFACT NODES
    # --------------------------------------------------------

    artifact_nodes = []

    support_nodes = []

    for node in graph.nodes():

        if node in KILL_CHAIN_ORDER:
            continue

        is_support = False

        for keyword in SUPPORTING_KEYWORDS:

            if keyword.lower() in str(node).lower():

                support_nodes.append(node)

                is_support = True

                break

        if not is_support:

            artifact_nodes.append(node)

    # --------------------------------------------------------
    # ARTIFACT COLORS
    # --------------------------------------------------------

    artifact_colors = []

    for node in artifact_nodes:

        assigned = False

        for source, target in graph.edges():

            if (

                target == node

                and

                source in CATEGORY_COLORS
            ):

                artifact_colors.append(

                    CATEGORY_COLORS[source]
                )

                assigned = True

                break

        if not assigned:

            artifact_colors.append(

                CATEGORY_COLORS["artifact"]
            )

    # --------------------------------------------------------
    # ARTIFACT SIZES
    # --------------------------------------------------------

    artifact_sizes = [

        get_node_size(node)

        for node in artifact_nodes
    ]

    # --------------------------------------------------------
    # DRAW ARTIFACT NODES
    # --------------------------------------------------------

    nx.draw_networkx_nodes(

        graph,

        pos,

        nodelist=artifact_nodes,

        node_color=artifact_colors,

        node_size=artifact_sizes,

        alpha=0.90
    )

    # --------------------------------------------------------
    # FILTER VALID EDGES
    # --------------------------------------------------------

    valid_edges = []

    for source, target in graph.edges():

        if source in pos and target in pos:

            valid_edges.append(

                (source, target)
            )

    # --------------------------------------------------------
    # DRAW EDGES
    # --------------------------------------------------------

    nx.draw_networkx_edges(

        graph,

        pos,

        edgelist=valid_edges,

        arrows=True,

        arrowsize=28,

        width=2.6,

        edge_color="#616161",

        alpha=0.72
    )

    # --------------------------------------------------------
    # LABELS
    # --------------------------------------------------------

    labels = {}

    for node in pos:

        if node in STAGE_LABELS:

            labels[node] = STAGE_LABELS[node]

        else:

            labels[node] = node

    nx.draw_networkx_labels(

        graph,

        pos,

        labels=labels,

        font_size=10,

        font_weight="bold"
    )

    # --------------------------------------------------------
    # SUPPORTING INFRASTRUCTURE PANEL
    # --------------------------------------------------------

    support_text = (
        "SUPPORTING INFRASTRUCTURE\n"
        "────────────────────────\n"
    )

    for node in sorted(support_nodes):

        support_text += f"• {node}\n"

    plt.text(

        0.80,

        0.24,

        support_text,

        transform=plt.gca().transAxes,

        fontsize=11,

        verticalalignment="top",

        bbox={

            "boxstyle": "round,pad=0.7",

            "facecolor": "#ECEFF1",

            "edgecolor": "#455A64",

            "linewidth": 2
        }
    )

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    plt.title(

        "C.D.K.C.I.A.E Kill-Chain Threat Intelligence Graph",

        fontsize=26,

        fontweight="bold"
    )

    # --------------------------------------------------------
    # FOOTER
    # --------------------------------------------------------

    plt.figtext(

        0.5,

        0.025,

        (
            "Attack Flow: "
            "Initial Access → Execution → "
            "Privilege Escalation → "
            "Exfiltration → Monetization"
        ),

        ha="center",

        fontsize=13,

        fontweight="bold"
    )

    # --------------------------------------------------------
    # TIMESTAMP
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(

        "%d-%m-%Y %H:%M:%S"
    )

    plt.figtext(

        0.01,

        0.01,

        f"Generated: {timestamp}",

        fontsize=9
    )

    # --------------------------------------------------------
    # OUTPUT DIRECTORY
    # --------------------------------------------------------

    os.makedirs(

        "outputs",

        exist_ok=True
    )

    # --------------------------------------------------------
    # EXPORT PNG
    # --------------------------------------------------------

    plt.savefig(

        "outputs/threat_graph.png",

        dpi=300,

        bbox_inches="tight"
    )

    # --------------------------------------------------------
    # FINAL LAYOUT FIX
    # --------------------------------------------------------

    plt.subplots_adjust(top=0.90)

    # --------------------------------------------------------
    # CLEANUP
    # --------------------------------------------------------

    plt.axis("off")

    plt.tight_layout()

    plt.show()