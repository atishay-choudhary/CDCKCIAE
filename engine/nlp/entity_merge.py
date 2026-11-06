"""
Merges regex and NER entities into one artifact record (FR-2.4).

Regex results go first and win ties. The two input sets are also returned
unchanged (regex_entities, ner_entities) for the side-by-side view.

Regex results go first and win ties. An entity is kept once, under
its first type, compared case-insensitively across all types, so the
same string found by both extractors (or tagged with two NER types)
is not repeated.
"""


def merge_entities(regex_entities, ner_entities):

    merged = {
        kind: list(values)
        for kind, values in regex_entities.items() if values
    }

    taken = {v.lower() for values in merged.values() for v in values}

    removed = 0

    for kind, values in ner_entities.items():

        for value in values:

            key = value.lower()

            if key in taken:
                removed += 1
                continue

            taken.add(key)
            merged.setdefault(kind, []).append(value)

    return {
        "entities": {k: sorted(v) for k, v in sorted(merged.items())},
        # kept apart too, so the two extractors can be compared (UC-2)
        "regex_entities": {k: sorted(v) for k, v in sorted(regex_entities.items()) if v},
        "ner_entities": {k: sorted(v) for k, v in sorted(ner_entities.items()) if v},
        "regex_count": sum(len(v) for v in regex_entities.values()),
        "ner_count": sum(len(v) for v in ner_entities.values()),
        "duplicates_removed": removed
    }
