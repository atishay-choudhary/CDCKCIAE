"""
Crawled-document store (FR-1.5 audit trail, FR-8.1 dark-web test set).

Every document the pipelines collect is stored, redacted and
de-duplicated, in the database (table corpus_document).

Redaction replaces personal / network identifiers with placeholders of
the same kind, so downstream extractors still see the same signal
types (an IP stays an IP) while no real leaked data is stored.
"""

import re

from engine import datastore


_EMAIL = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_IPV4 = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_LONG_NUMBER = re.compile(r"\b\d{12,19}\b")


def redact(text):

    text = _EMAIL.sub("user@example.invalid", text)
    text = _IPV4.sub("10.0.0.1", text)
    text = _SSN.sub("000-00-0000", text)

    return _LONG_NUMBER.sub("0000000000000000", text)


def save_document(url, text, source_type):
    """
    Stores the redacted page in the database (corpus_document),
    de-duplicated by content hash. source_type: "mock" or "live".
    """

    datastore.save_document(url, redact(text), source_type)
