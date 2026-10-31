"""
Named-entity extraction (O2: FR-2.1), alongside the regex extractors.

spaCy's statistical NER supplies organisations, locations and products.
It has no notion of threat actors or malware, so an EntityRuler built
from the MITRE ATT&CK bundle already in datasets/ adds:

- threat_actors : intrusion-set names and aliases
- malware_tools : malware / tool names and aliases

Ruler matching is exact-case (ATT&CK's spelling) for every name. Names
of 6+ characters or containing a digit are also matched in any case,
since forum text is mostly lowercase. Any name that fires on ordinary
vulnerability text is dropped entirely (words like "Page", "route" or
"Chromium" are ATT&CK names). Names under 4 characters or equal to a
stop word are never used.

If spaCy or the model is unavailable, extraction returns {} with one
warning instead of failing the pipeline.

Setup:
    pip install spacy
    python -m spacy download en_core_web_sm
"""

import json
import os


MODEL = "en_core_web_sm"
MITRE_FILE = "datasets/mitre/raw/enterprise-attack.json"
GENERIC_TEXT_FILE = "datasets/cves/raw/nvdcve-2.0-recent.json"
CACHE_PATH = "models/attack_names.json"

MIN_NAME_LENGTH = 4
MIN_ANY_CASE_LENGTH = 6

LABEL_TO_TYPE = {
    "ORG": "organizations",
    "GPE": "locations",
    "LOC": "locations",
    "PRODUCT": "products",
    "THREAT_ACTOR": "threat_actors",
    "MALWARE_TOOL": "malware_tools",
}

_nlp = None


def _generic_text_hits(names):
    """
    Lowercased names that fire (any case) on ordinary vulnerability
    text, i.e. are also common words.
    """

    import spacy

    try:
        with open(GENERIC_TEXT_FILE, "r", encoding="utf-8") as f:
            texts = [
                v["cve"]["descriptions"][0]["value"]
                for v in json.load(f)["vulnerabilities"]
            ]

    except FileNotFoundError:
        return None

    nlp = spacy.blank("en")

    nlp.add_pipe(
        "entity_ruler", config={"phrase_matcher_attr": "LOWER"}
    ).add_patterns([{"label": "NAME", "pattern": n} for n in names])

    return {
        ent.text.lower()
        for doc in nlp.pipe(texts, batch_size=200)
        for ent in doc.ents
    }


def attack_names():
    """
    {"THREAT_ACTOR": [...], "MALWARE_TOOL": [...],
     "ANY_CASE": [names also matched in any case]} from ATT&CK;
    cached after the first build.
    """

    if os.path.exists(CACHE_PATH):

        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)

    try:
        with open(MITRE_FILE, "r", encoding="utf-8") as f:
            objects = json.load(f)["objects"]

    except FileNotFoundError:
        return {}

    from spacy.lang.en.stop_words import STOP_WORDS

    kinds = {
        "intrusion-set": "THREAT_ACTOR",
        "malware": "MALWARE_TOOL",
        "tool": "MALWARE_TOOL",
    }

    names = {"THREAT_ACTOR": set(), "MALWARE_TOOL": set()}

    for obj in objects:

        label = kinds.get(obj.get("type"))

        if (
            label is None
            or obj.get("revoked")
            or obj.get("x_mitre_deprecated")
        ):
            continue

        for name in [obj["name"], *obj.get("aliases", []),
                     *obj.get("x_mitre_aliases", [])]:

            if (
                len(name) >= MIN_NAME_LENGTH
                and name.lower() not in STOP_WORDS
            ):
                names[label].add(name)

    # Drop every name that also fires on ordinary text ("Page", "route").
    # Without the generic-text file no filtering is possible, so any-case
    # matching stays off.
    common = _generic_text_hits({n for v in names.values() for n in v})

    if common is not None:
        names = {
            label: {n for n in values if n.lower() not in common}
            for label, values in names.items()
        }

    names = {label: sorted(values) for label, values in names.items()}

    names["ANY_CASE"] = (
        sorted(
            n for values in names.values() for n in values
            if len(n) >= MIN_ANY_CASE_LENGTH or any(c.isdigit() for c in n)
        )
        if common is not None else []
    )

    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)

    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(names, f)

    return names


def _load():

    global _nlp

    if _nlp is None:

        try:
            import spacy

            nlp = spacy.load(
                MODEL,
                disable=["parser", "lemmatizer", "tagger", "attribute_ruler"]
            )

        except (ImportError, OSError):
            print(
                "[!] spaCy NER unavailable (pip install spacy; "
                f"python -m spacy download {MODEL}); using regex only."
            )
            _nlp = False
            return _nlp

        names = attack_names()

        any_case = set(names.get("ANY_CASE", []))

        patterns = []

        for label in ("THREAT_ACTOR", "MALWARE_TOOL"):

            for name in names.get(label, []):

                patterns.append({"label": label, "pattern": name})

                if name in any_case:
                    patterns.append({
                        "label": label,
                        "pattern": [
                            {"LOWER": t.lower_} for t in nlp.make_doc(name)
                        ]
                    })

        if patterns:
            nlp.add_pipe("entity_ruler", before="ner").add_patterns(patterns)

        _nlp = nlp

    return _nlp


def extract_named_entities(text):
    """
    {"organizations": [...], "locations": [...], "products": [...],
     "threat_actors": [...], "malware_tools": [...]} (non-empty only).
    """

    nlp = _load()

    if not nlp:
        return {}

    found = {}

    for ent in nlp(text).ents:

        kind = LABEL_TO_TYPE.get(ent.label_)

        if kind:
            found.setdefault(kind, set()).add(ent.text.strip())

    return {kind: sorted(values) for kind, values in sorted(found.items())}