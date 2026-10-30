"""
Crawled-document store (FR-1.5 audit trail, FR-8.1 dark-web test set).

Every document the pipelines collect is appended, redacted and
de-duplicated, to datasets/crawled/documents.jsonl.

Redaction replaces personal / network identifiers with placeholders of
the same kind, so downstream extractors still see the same signal
types (an IP stays an IP) while no real leaked data is kept on disk.
"""

import hashlib
import json
import os
import re
from datetime import datetime, timezone


CORPUS_PATH = "datasets/crawled/documents.jsonl"

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
    source_type: "mock" or "live".
    """

    text = redact(text)

    digest = hashlib.sha1(text.encode("utf-8")).hexdigest()

    os.makedirs(os.path.dirname(CORPUS_PATH), exist_ok=True)

    if os.path.exists(CORPUS_PATH):

        with open(CORPUS_PATH, "r", encoding="utf-8") as f:

            if any(json.loads(line)["sha1"] == digest for line in f):
                return

    with open(CORPUS_PATH, "a", encoding="utf-8") as f:

        f.write(json.dumps({
            "sha1": digest,
            "url": url,
            "source_type": source_type,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "text": text
        }) + "\n")