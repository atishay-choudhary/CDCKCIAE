"""
NLP preprocessing module.

Responsible for:
- tokenization
- stopword removal
- token frequency analysis
"""

import re

from collections import Counter


# ============================================================
# STOPWORDS
# ============================================================

STOPWORDS = {

    "the",
    "is",
    "a",
    "an",
    "and",
    "or",
    "to",
    "of",
    "for",
    "in",
    "on",
    "with",
    "that",
    "this",
    "it",
    "was",
    "are",
    "be",
    "by",
    "as",
    "at",
    "from",
    "into",
    "after",
    "still",
    "only",
    "some",
    "might"
}


# ============================================================
# TOKENIZATION
# ============================================================

def tokenize(text):

    """
    Splits text into tokens.
    """

    text = text.lower()

    tokens = re.findall(
        r"\b[a-zA-Z0-9_-]+\b",
        text
    )

    return tokens


# ============================================================
# STOPWORD REMOVAL
# ============================================================

def remove_stopwords(tokens):

    """
    Removes common stopwords.
    """

    filtered_tokens = [

        token

        for token in tokens

        if token not in STOPWORDS
    ]

    return filtered_tokens


# ============================================================
# TOKEN FREQUENCY
# ============================================================

def token_frequency(tokens):

    """
    Calculates token frequency.
    """

    return Counter(tokens)


# ============================================================
# FULL NLP PREPROCESSING PIPELINE
# ============================================================

def preprocess_text(text):

    """
    Full NLP preprocessing pipeline.
    """

    tokens = tokenize(text)

    filtered_tokens = remove_stopwords(
        tokens
    )

    frequencies = token_frequency(
        filtered_tokens
    )

    return {

        "tokens": filtered_tokens,

        "frequencies": frequencies
    }