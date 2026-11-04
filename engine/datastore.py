"""
The engine's only door to stored data.

Everything the engine reads or writes at run time (reference datasets,
labelled sets, trained models, caches, the source registry, the crawl
corpus, the audit trail, generated reports) goes through this module and
lives in the database (SRS 6.1 "migration of persistence from JSON files
to Database", System Design DFD stores D1, D3, D4, D6, D7).

The implementation is backend/core/store.py (Django ORM; SQLite for
development, PostgreSQL for deployment). The engine itself imports no
Django: the first call below connects to it on demand, so
`python main.py` and the web backend use the same database.

Raw downloads (NVD, CISA, MITRE) are only ever *ingested* into the
database (python backend/manage.py sync_reference); after that nothing
reads them.
"""

import os
import sys

_store = None


def use(store):
    """Install a store explicitly (tests, the backend)."""

    global _store

    _store = store


def get():

    global _store

    if _store is None:
        _store = _connect()

    return _store


def _connect():

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    backend = os.path.join(root, "backend")

    if backend not in sys.path:
        sys.path.insert(0, backend)

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cdkciae_backend.settings")

    import django

    from django.apps import apps

    if not apps.ready:
        django.setup()

    from core.store import DatabaseStore

    return DatabaseStore()


# ----------------------------------------------------------- reference

def nvd_vulnerabilities(recent_only=False):
    """[{"cve": {id, vulnStatus, descriptions, metrics, ...}}, ...]"""
    return get().nvd_vulnerabilities(recent_only)


def nvd_by_ids(ids):
    """{cve_id: compact NVD record} for the ids held in the database."""
    return get().nvd_by_ids(ids)


def kev_entries():
    """[{"cve_id", "vendor", "product", "name"}, ...]"""
    return get().kev_entries()


def mitre_objects():
    """The ATT&CK STIX objects (what the bundle's "objects" list held)."""
    return get().mitre_objects()


def historical_attacks():
    return get().historical_attacks()


# ------------------------------------------------- labelled set + models

def save_labelled(task, rows):
    return get().save_labelled(task, rows)


def labelled_split(task):
    """(X_train, y_train, X_test, y_test)"""
    return get().labelled_split(task)


def save_model(task, name, blob, meta=None):
    return get().save_model(task, name, blob, meta or {})


def load_model(task):
    """Serialised model bytes, or None."""
    return get().load_model(task)


def cache_get(key):
    return get().cache_get(key)


def cache_set(key, value):
    return get().cache_set(key, value)


# ------------------------------------------------------ crawling + audit

def crawl_sources(kind="live"):
    """[{"name", "url", "category", "search"}, ...] (kind live or mock)."""
    return get().crawl_sources(kind)


def mock_page(url):
    return get().mock_page(url)


def save_document(url, text, source_type):
    return get().save_document(url, text, source_type)


def annotation_replace(task, rows):
    """Replaces the task's sampled snippets (labels start empty)."""
    return get().annotation_replace(task, rows)


def annotation_rows(task):
    """[{id, source, source_type, text, <label columns>}, ...]"""
    return get().annotation_rows(task)


def annotation_label(task, sample_id, labels):
    """Merges {column: value} into one sample's labels."""
    return get().annotation_label(task, sample_id, labels)


def latest_file(kind, name=None):
    """Newest generated file (bytes) of that kind, or None."""
    return get().latest_file(kind, name)


def documents():
    """[{"sha1", "url", "source_type", "text"}, ...]"""
    return get().documents()


def log_event(event):
    return get().log_event(event)


# -------------------------------------------------------------- reports

def save_report(name, data):
    return get().save_report(name, data)


def get_report(name):
    return get().get_report(name)


def save_file(kind, name, content):
    return get().save_file(kind, name, content)
