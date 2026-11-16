"""
Noise filters for extracted entities (FR-2.1, FR-2.3).

Two kinds of false positive dominated the hand-labelled scores:

* the domain regex matched anything shaped like "a.b": Java packages
  (org.minidns.record), file names (exploit.py, dump.zip), reserved
  names (host.invalid). A real domain ends in a real top-level domain.
* spaCy tagged ordinary threat vocabulary as organisations, places or
  products ("Exploit", "Payload", "Initial Access"), and also tagged
  onion addresses, e-mail addresses and CVE ids as organisations.

Both filters are pure functions of the text, so they are tested without
spaCy or a database. The word list is deliberately short and made of
words that describe an activity or a marketplace, never a company name.
"""

import re
from pathlib import Path


_TLD_FILE = Path(__file__).resolve().parents[1] / "extractors" / "tlds.txt"

# RFC 2606 / 6761 names that can never be a real public site, and file
# extensions that are also country codes (setup.py, run.sh, dump.zip).
RESERVED_TLDS = {"invalid", "test", "example", "localhost", "local"}
FILE_LIKE_TLDS = {"py", "sh", "zip", "mov"}


def _load_tlds():

    try:
        lines = _TLD_FILE.read_text(encoding="ascii").splitlines()
    except OSError:
        return None

    return {l.strip() for l in lines if l.strip() and not l.startswith("#")} | {"onion"}


_TLDS = _load_tlds()


def valid_domain(text):
    """
    True when `text` looks like a domain a real site could have: every
    label is 1-63 characters, the last one is a known top-level domain,
    and it is not a reserved name or a file name.
    """

    labels = text.lower().strip(".").split(".")

    if len(labels) < 2 or any(not 0 < len(l) <= 63 for l in labels):
        return False

    tld = labels[-1]

    if tld in RESERVED_TLDS or tld in FILE_LIKE_TLDS:
        return False

    # without the TLD file nothing more can be checked
    return _TLDS is None or tld in _TLDS


# Words that describe an attack activity or a marketplace. A single-word
# entity equal to one of these is a topic, not an organisation or place.
THREAT_VOCABULARY = frozenset("""
exploit exploits exploitation payload payloads ransomware malware spyware
trojan botnet phishing credential credentials password passwords leak leaks
leaked dump dumps database databases breach breaches vulnerability
vulnerabilities zeroday backdoor rootkit keylogger shell shells access
exfiltrate exfiltration infiltration lateral escalation persistence evasion
reconnaissance weaponization delivery installation command control
market marketplace vendor vendors escrow shop store forum hosting
bitcoin btc monero xmr crypto cryptocurrency wallet carding fullz cvv
hacker hackers hacking hack cracked crack stealer loader dropper
onion tor darknet deepweb
initial privilege defense actions objectives discovery collection impact
resource development execution
""".split())

# two- and three-letter places that are real, unlike "IT" or "ID"
SHORT_PLACES = {"us", "uk", "eu", "uae"}

_ADDRESS_LIKE = re.compile(r"@|://|\.onion\b|\bCVE-\d{4}-\d+\b|^[\w.-]+\.[a-z]{2,}$", re.I)


def keep_named_entity(text):
    """
    False for spaCy entities that are noise: too short, digits only,
    an address (e-mail, URL, onion, CVE id, bare domain), or made only
    of threat vocabulary ("Initial Access", "Exploit").
    """

    text = text.strip()

    if text.lower() in SHORT_PLACES:
        return True

    if len(text) < 3 or not any(c.isalpha() for c in text):
        return False

    if _ADDRESS_LIKE.search(text):
        return False

    words = re.findall(r"[A-Za-z]+", text.lower())

    return not all(w in THREAT_VOCABULARY for w in words)
