"""
Attack path prediction and centrality analysis (O3: FR-5.2, FR-5.3).

Stage structure comes from the existing PROPAGATION_RULES. Edge
probabilities are learned from MITRE ATT&CK intrusion sets:

    P(B | A) = groups using both A and B / groups using A

(Laplace-smoothed). This is conditional co-usage, not observed
temporal order, which ATT&CK does not record.

Path likelihood is the product of edge probabilities, so longer
paths are less likely. The most-likely path is the shortest path
under cost = -ln(p). Centrality is computed on the same weighted graph.
"""

import math
from collections import Counter
from itertools import islice

import networkx as nx

from engine import datastore
from engine.intelligence.propagation_engine import PROPAGATION_RULES


CACHE_KEY = "path_transitions"

# ATT&CK tactic -> stage node. The current bundle renamed
# defense-evasion to "stealth"; both are accepted.
TACTIC_TO_STAGE = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "stealth": "Defense Evasion",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
}

STAGE_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
]


def load_attack_data():
    """
    Returns (technique_stages, group_stages):
    - technique_stages : {"T1190": {"Initial Access"}, ...}
    - group_stages     : one set of stages per intrusion set
    """

    objects = datastore.mitre_objects()

    if not objects:
        raise FileNotFoundError("ATT&CK data not in the database")

    def active(o):
        return not o.get("revoked") and not o.get("x_mitre_deprecated")

    def stages(o):
        return {
            TACTIC_TO_STAGE[p["phase_name"]]
            for p in o.get("kill_chain_phases", [])
            if p["phase_name"] in TACTIC_TO_STAGE
        }

    techniques = {
        o["id"]: o for o in objects
        if o.get("type") == "attack-pattern" and active(o)
    }

    technique_stages = {
        ref["external_id"]: stages(o)
        for o in techniques.values()
        for ref in o["external_references"]
        if ref.get("source_name") == "mitre-attack"
    }

    groups = {
        o["id"] for o in objects
        if o.get("type") == "intrusion-set" and active(o)
    }

    used = {}

    for o in objects:

        if (
            o.get("type") == "relationship"
            and o["relationship_type"] == "uses"
            and o["source_ref"] in groups
            and o["target_ref"] in techniques
            and not o.get("revoked")
        ):
            used.setdefault(o["source_ref"], set()).update(
                stages(techniques[o["target_ref"]])
            )

    return technique_stages, [used[g] for g in sorted(used)]


def learn_transitions(group_stages):

    usage = Counter()
    pairs = Counter()

    for stages in group_stages:

        for a, successors in PROPAGATION_RULES.items():

            if a in stages:

                usage[a] += 1

                for b in successors:
                    pairs[(a, b)] += int(b in stages)

    return {
        f"{a}->{b}": (pairs[(a, b)] + 1) / (usage[a] + 2)
        for a, successors in PROPAGATION_RULES.items()
        for b in successors
    }


def uniform_transitions():

    return {
        f"{a}->{b}": 1 / len(successors)
        for a, successors in PROPAGATION_RULES.items()
        for b in successors
    }


def get_transitions():
    """
    Cached learned transitions (store_cache table); learned from the
    ATT&CK data in the database on first use. Falls back to uniform if
    that data has not been loaded.
    """

    cached = datastore.cache_get(CACHE_KEY)

    if cached:
        return cached, "learned (ATT&CK groups)"

    try:
        _, groups = load_attack_data()

    except FileNotFoundError:
        return uniform_transitions(), "uniform (ATT&CK data not loaded)"

    transitions = learn_transitions(groups)

    datastore.cache_set(CACHE_KEY, transitions)

    return transitions, "learned (ATT&CK groups)"


def build_graph(transitions):

    graph = nx.DiGraph()

    for key, probability in transitions.items():

        a, b = key.split("->")

        graph.add_edge(
            a,
            b,
            probability=probability,
            cost=-math.log(probability)
        )

    return graph


def most_likely_paths(graph, entry, k=3):
    """
    Top-k paths from `entry` to a terminal stage (FR-5.2).
    Returns [(path, likelihood), ...], most likely first.
    """

    terminals = [
        n for n in graph
        if graph.out_degree(n) == 0 and nx.has_path(graph, entry, n)
    ]

    if entry in terminals or graph.out_degree(entry) == 0:
        return [([entry], 1.0)]

    candidates = []

    for terminal in terminals:

        for path in islice(
            nx.shortest_simple_paths(graph, entry, terminal, weight="cost"),
            k
        ):
            candidates.append((
                path,
                math.prod(
                    graph[a][b]["probability"]
                    for a, b in zip(path, path[1:])
                )
            ))

    return sorted(candidates, key=lambda c: -c[1])[:k]


def centrality(graph):
    """
    Critical-stage ranking (FR-5.3): betweenness on path cost
    (chokepoints) and PageRank on probability (attack-flow sink).
    """

    betweenness = nx.betweenness_centrality(graph, weight="cost")
    pagerank = nx.pagerank(graph, weight="probability")

    return sorted(
        (
            {
                "stage": n,
                "betweenness": round(betweenness[n], 4),
                "pagerank": round(pagerank[n], 4)
            }
            for n in graph
        ),
        key=lambda r: (-r["betweenness"], -r["pagerank"])
    )


def predict_attack_paths(kill_chain, k=3):
    """
    Pipeline entry point. `kill_chain` is the list of observed stages.
    """

    transitions, source = get_transitions()

    graph = build_graph(transitions)

    entries = [s for s in STAGE_ORDER if s in kill_chain]

    return {
        "transition_source": source,
        "entries": entries,
        "unmapped_stages": sorted(set(kill_chain) - set(graph)),
        "paths": [
            {
                "entry": entry,
                "path": path,
                "likelihood": round(likelihood, 4)
            }
            for entry in entries
            for path, likelihood in most_likely_paths(graph, entry, k)
        ],
        "centrality": centrality(graph)
    }
