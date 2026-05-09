"""
TF-IDF analysis module.

Identifies important threat terms.
"""

from sklearn.feature_extraction.text import (
    TfidfVectorizer
)


# ============================================================
# TF-IDF ANALYSIS
# ============================================================

def extract_important_terms(

    documents,

    top_n=10
):

    """
    Extracts top TF-IDF terms.
    """

    if not documents:

        return []

    vectorizer = TfidfVectorizer(

        stop_words="english"
    )

    tfidf_matrix = vectorizer.fit_transform(
        documents
    )

    feature_names = vectorizer.get_feature_names_out()

    scores = tfidf_matrix.sum(axis=0)

    scored_terms = [

        (
            feature_names[i],
            scores[0, i]
        )

        for i in range(len(feature_names))
    ]

    scored_terms = sorted(

        scored_terms,

        key=lambda x: x[1],

        reverse=True
    )

    return scored_terms[:top_n]