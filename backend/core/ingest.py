"""
Pulls reference data into the database (DFD D3) and seeds the source
registry. Used by `manage.py sync_reference`. Two origins:

  * pull   : straight from the publishers (CISA KEV, MITRE ATT&CK on
             GitHub, NVD API 2.0) into the database, no file kept;
  * import : once, from files you already downloaded.

After either, the engine reads only the database.
"""

import json
import time
from datetime import datetime, timedelta, timezone

import requests
from django.db import transaction

from core.models import (
    AttackObject,
    CrawlSource,
    CveReference,
    HistoricalAttack,
    KevEntry,
    NvdRecord,
)

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

MITRE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_WINDOW_DAYS = 120          # the API's maximum date range

CHUNK = 1000

CLIENT = {"User-Agent": "CDKCIAE-research/1.0"}


# ------------------------------------------------------------------ NVD

def compact_cve(cve):
    """The parts of an NVD record the engine uses."""

    metrics = {}

    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):

        entries = cve.get("metrics", {}).get(key)

        if entries:
            data = entries[0].get("cvssData", {})
            metrics[key] = [{"cvssData": {
                k: data.get(k) for k in ("vectorString", "baseScore", "baseSeverity")
            }}]

    return {
        "id": cve["id"],
        "vulnStatus": cve.get("vulnStatus"),
        "published": cve.get("published"),
        "descriptions": cve.get("descriptions", []),
        "metrics": metrics,
    }


def ingest_nvd(vulnerabilities, recent=False):
    """vulnerabilities: NVD items ({"cve": {...}}). Returns the count."""

    kev = dict(
        KevEntry.objects.values_list("cve_id", "vendor")
    )

    count = 0

    batch = []

    def flush():

        if not batch:
            return

        references = [
            CveReference(
                cve_id=r["id"],
                description=_english(r)[:2000],
                severity_score=_score(r),
                affected_platforms=kev.get(r["id"], ""),
                exploit_availability=r["id"] in kev,
            )
            for r in batch
        ]

        with transaction.atomic():

            CveReference.objects.bulk_create(
                references, update_conflicts=True, unique_fields=["cve_id"],
                update_fields=["description", "severity_score"],
            )

            NvdRecord.objects.bulk_create(
                [NvdRecord(cve_id=r["id"], in_recent=recent, record=r)
                 for r in batch],
                update_conflicts=True, unique_fields=["cve_id"],
                update_fields=["in_recent", "record"],
            )

        batch.clear()

    for item in vulnerabilities:

        batch.append(compact_cve(item["cve"]))

        count += 1

        if len(batch) >= CHUNK:
            flush()

    flush()

    return count


def _english(record):

    return next(
        (d["value"] for d in record["descriptions"] if d.get("lang") == "en"),
        record["descriptions"][0]["value"] if record["descriptions"] else "",
    )


def _score(record):

    try:
        return record["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]

    except (KeyError, IndexError):
        return None


def fetch_nvd(start, end, api_key=None, log=print):
    """
    Yields NVD items published between start and end (datetimes), in
    120-day windows, paged. Without an API key NVD allows 5 requests per
    30 seconds, so the loop waits between calls.
    """

    headers = {**CLIENT, **({"apiKey": api_key} if api_key else {})}

    pause = 0.7 if api_key else 6.5

    cursor = start

    while cursor < end:

        stop = min(cursor + timedelta(days=NVD_WINDOW_DAYS), end)

        index = 0

        while True:

            response = requests.get(
                NVD_URL,
                params={
                    "pubStartDate": cursor.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "pubEndDate": stop.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "resultsPerPage": 2000,
                    "startIndex": index,
                },
                headers=headers,
                timeout=120,
            )

            response.raise_for_status()

            page = response.json()

            yield from page.get("vulnerabilities", [])

            index += page.get("resultsPerPage", 0)

            log(f"  NVD {cursor:%Y-%m-%d}: {min(index, page['totalResults'])}"
                f"/{page['totalResults']}")

            if index >= page.get("totalResults", 0):
                break

            time.sleep(pause)

        cursor = stop

        time.sleep(pause)


def fetch_nvd_recent(api_key=None, days=8, log=print):
    """The last few days' modifications: the "recent" feed."""

    end = datetime.now(timezone.utc).replace(tzinfo=None)

    headers = {**CLIENT, **({"apiKey": api_key} if api_key else {})}

    index = 0

    while True:

        response = requests.get(
            NVD_URL,
            params={
                "lastModStartDate": (end - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000"),
                "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": 2000,
                "startIndex": index,
            },
            headers=headers,
            timeout=120,
        )

        response.raise_for_status()

        page = response.json()

        yield from page.get("vulnerabilities", [])

        index += page.get("resultsPerPage", 0)

        if index >= page.get("totalResults", 0):
            break

        time.sleep(0.7 if api_key else 6.5)


# ------------------------------------------------------------------ KEV

def ingest_kev(vulnerabilities):

    entries = [
        KevEntry(
            cve_id=v["cveID"],
            vendor=v.get("vendorProject", ""),
            product=v.get("product", ""),
            name=v.get("vulnerabilityName", ""),
        )
        for v in vulnerabilities
    ]

    with transaction.atomic():

        KevEntry.objects.bulk_create(
            entries, update_conflicts=True, unique_fields=["cve_id"],
            update_fields=["vendor", "product", "name"],
        )

        # mirror the catalogue onto the design's cve_reference rows
        known = {
            c.cve_id: c
            for c in CveReference.objects.filter(
                pk__in=[e.cve_id for e in entries]
            )
        }

        for entry in entries:

            if entry.cve_id in known:
                known[entry.cve_id].exploit_availability = True
                known[entry.cve_id].affected_platforms = (
                    f"{entry.vendor} {entry.product}".strip()
                )

        CveReference.objects.bulk_update(
            known.values(), ["exploit_availability", "affected_platforms"],
            batch_size=CHUNK,
        )

    return len(entries)


def fetch_kev():

    response = requests.get(KEV_URL, headers=CLIENT, timeout=120)

    response.raise_for_status()

    return response.json().get("vulnerabilities", [])


# ---------------------------------------------------------------- MITRE

def ingest_mitre(objects):

    wanted = [o for o in objects if o.get("id") and o.get("type")]

    with transaction.atomic():

        AttackObject.objects.all().delete()

        AttackObject.objects.bulk_create(
            (AttackObject(stix_id=o["id"], object_type=o["type"], record=o)
             for o in wanted),
            batch_size=CHUNK, ignore_conflicts=True,
        )

    return len(wanted)


def fetch_mitre():

    response = requests.get(MITRE_URL, headers=CLIENT, timeout=300)

    response.raise_for_status()

    return response.json().get("objects", [])


# ----------------------------------------------------------- historical

def ingest_historical(attacks):

    with transaction.atomic():

        HistoricalAttack.objects.all().delete()

        HistoricalAttack.objects.bulk_create(
            HistoricalAttack(attack_name=a["attack_name"], record=a)
            for a in attacks
        )

    return len(attacks)


# -------------------------------------------------------------- sources

DEFAULT_SOURCES = [
    {
        "name": "Ahmia (clearnet search, via Tor)",
        "url": "https://ahmia.fi/search/",
        "category": "search_engine",
        "search": {
            "url": "https://ahmia.fi/search/",
            "param": "q",
            "form_page": "https://ahmia.fi/",
        },
    },
]


def seed_sources(mock_pages=None):
    """
    Adds the default live source if the registry has none, and the mock
    pages (name -> html) when given. Existing rows are left alone.
    """

    if not CrawlSource.objects.filter(kind="live").exists():

        for source in DEFAULT_SOURCES:
            CrawlSource.objects.get_or_create(
                name=source["name"], defaults={**source, "kind": "live"}
            )

    for filename, html in (mock_pages or {}).items():

        CrawlSource.objects.update_or_create(
            name=f"mock:{filename}",
            defaults={
                "url": f"mock://{filename}", "category": "mock",
                "kind": "mock", "content": html,
            },
        )


def load_json(path):

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
