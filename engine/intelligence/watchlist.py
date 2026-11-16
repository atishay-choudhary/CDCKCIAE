"""
Watchlist matching (assets the user told us to watch).

Until now an "asset" was whatever the text happened to contain (an e-mail
address, an IP, a confirmed CVE), so exposure and FAIR said little about
the organisation actually being monitored. A watchlist fixes that: the
user lists the domains, e-mail addresses, IP addresses and names that are
theirs, with how much each matters, and only those that really appear in
the collected text become rated assets. Nothing on the list that is not
found raises the score.

Kinds:
    domain : example.com. Also matches sub-domains (mail.example.com) and
             the domain part of e-mail addresses (a@example.com).
    email  : jo@example.com
    ip     : 203.0.113.7 (IPv4, exact)
    name   : a company, product or brand name, matched as whole words,
             ignoring case.

The module is pure apart from find_hits(), which reads the list through
engine.datastore.
"""

import ipaddress
import re

from engine import datastore
from engine.nlp.entity_filters import valid_domain


KINDS = ("domain", "email", "ip", "name")
CRITICALITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

MAX_NAME_LENGTH = 80
MIN_NAME_LENGTH = 3

_EMAIL = re.compile(r"^[A-Za-z0-9_.+-]+@([A-Za-z0-9.-]+)$")


def clean(kind, value):
    """
    The canonical form of a watched value, or ValueError with a message
    that can be shown to the user.
    """

    if kind not in KINDS:
        raise ValueError("kind must be one of: " + ", ".join(KINDS))

    value = " ".join(str(value).split())

    if kind == "domain":
        value = value.lower().removeprefix("www.")
        if not valid_domain(value):
            raise ValueError("not a valid domain, for example example.com")
        return value

    if kind == "email":
        match = _EMAIL.match(value)
        if not match or not valid_domain(match.group(1)):
            raise ValueError("not a valid e-mail address")
        return value.lower()

    if kind == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("not a valid IPv4 address") from None
        if address.version != 4:
            raise ValueError("only IPv4 addresses are supported")
        return str(address)

    if not MIN_NAME_LENGTH <= len(value) <= MAX_NAME_LENGTH or not any(c.isalpha() for c in value):
        raise ValueError(
            f"a name needs {MIN_NAME_LENGTH}-{MAX_NAME_LENGTH} characters and a letter"
        )

    return value


def _pattern(kind, value):

    escaped = re.escape(value)

    if kind == "domain":
        # sub-domains and e-mail addresses at the domain count
        return rf"(?<![\w-]){r'(?:[\w-]+\.)*'}{escaped}(?![\w-])"

    if kind == "ip":
        return rf"(?<![\d.]){escaped}(?![\d.])"

    if kind == "email":
        return rf"(?<![\w.+-]){escaped}(?![\w-])"

    return rf"(?<!\w){escaped}(?!\w)"


def find_hits(texts, items=None):
    """
    One hit per watched item that appears in the texts:
    {"type": "watch", "value", "kind", "criticality", "mentions"}.
    """

    if items is None:
        items = datastore.watchlist()

    if not items:
        return []

    joined = "\n".join(texts)

    hits = []

    for item in items:

        found = re.findall(_pattern(item["kind"], item["value"]), joined, re.IGNORECASE)

        if found:
            hits.append({
                "type": "watch",
                "value": item["value"],
                "kind": item["kind"],
                "criticality": item["criticality"],
                "mentions": len(found),
            })

    return hits
