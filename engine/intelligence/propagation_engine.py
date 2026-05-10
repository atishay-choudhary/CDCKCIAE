"""
Propagation Simulation Engine

Responsible for:
- attack traversal simulation
- lateral movement modeling
- propagation branching
- attack depth calculation
- propagation probability scoring
- severity escalation
"""

# ============================================================
# PROPAGATION RULES
# ============================================================

PROPAGATION_RULES = {

    "Initial Access": [

        "Execution",

        "Credential Access"
    ],

    "Execution": [

        "Privilege Escalation",

        "Persistence"
    ],

    "Credential Access": [

        "Lateral Movement",

        "Collection"
    ],

    "Privilege Escalation": [

        "Defense Evasion",

        "Lateral Movement"
    ],

    "Persistence": [

        "Lateral Movement"
    ],

    "Lateral Movement": [

        "Collection",

        "Command and Control"
    ],

    "Collection": [

        "Exfiltration"
    ],

    "Command and Control": [

        "Exfiltration"
    ],

    "Defense Evasion": [

        "Exfiltration"
    ]
}


# ============================================================
# SEVERITY ESCALATION
# ============================================================

def determine_severity(depth):

    """
    Escalates severity
    based on propagation depth.
    """

    if depth >= 6:
        return "CRITICAL"

    elif depth >= 4:
        return "HIGH"

    elif depth >= 2:
        return "MEDIUM"

    return "LOW"


# ============================================================
# PROPAGATION PROBABILITY
# ============================================================

def calculate_probability(depth):

    """
    Calculates propagation probability.
    """

    base_probability = 0.35

    increment = depth * 0.12

    probability = base_probability + increment

    if probability > 0.95:
        probability = 0.95

    return round(probability, 2)


# ============================================================
# TRAVERSAL ENGINE
# ============================================================

def traverse_attack_paths(

    current_stage,

    visited=None,

    current_path=None
):

    """
    Recursively traverses
    attack propagation paths.
    """

    if visited is None:
        visited = set()

    if current_path is None:
        current_path = []

    visited.add(current_stage)

    current_path.append(current_stage)

    next_stages = PROPAGATION_RULES.get(

        current_stage,

        []
    )

    # --------------------------------------------------------
    # TERMINAL NODE
    # --------------------------------------------------------

    if not next_stages:

        return [current_path.copy()]

    all_paths = []

    # --------------------------------------------------------
    # RECURSIVE TRAVERSAL
    # --------------------------------------------------------

    for next_stage in next_stages:

        if next_stage not in visited:

            generated_paths = traverse_attack_paths(

                next_stage,

                visited.copy(),

                current_path.copy()
            )

            all_paths.extend(generated_paths)

    return all_paths


# ============================================================
# GENERATE PROPAGATION MODEL
# ============================================================

def generate_propagation_model(

    kill_chain_stages
):

    """
    Generates propagation intelligence.
    """

    propagation_results = []

    seen_paths = set()

    for stage in kill_chain_stages:

        attack_paths = traverse_attack_paths(
            stage
        )

        for path in attack_paths:

            path_key = tuple(path)

            if path_key in seen_paths:
                continue

            seen_paths.add(path_key)

            depth = len(path)

            probability = calculate_probability(
                depth
            )

            severity = determine_severity(
                depth
            )

            propagation_results.append({

                "entry_point": stage,

                "path": path,

                "depth": depth,

                "probability": probability,

                "severity": severity
            })

    return propagation_results


# ============================================================
# SUMMARIZE PROPAGATION
# ============================================================

def summarize_propagation(

    propagation_results
):

    """
    Generates compact
    propagation summary.
    """

    summary = []

    for result in propagation_results:

        path_string = " → ".join(

            result["path"]
        )

        summary.append({

            "path": path_string,

            "probability": result[
                "probability"
            ],

            "severity": result[
                "severity"
            ],

            "depth": result[
                "depth"
            ]
        })

    return summary