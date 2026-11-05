"""
Loads a documented list of live sources into the registry (FR-1.3).

    python manage.py import_sources config/dw_sources.json
    python manage.py import_sources list.json --disable-missing

Each entry: name, url, category, optional search {url, param, form_page}.
See docs/SOURCES.md for how sources must be chosen.
"""

import json
from urllib.parse import urlparse

from django.core.management.base import BaseCommand, CommandError

from core.models import CrawlSource


def validate(entry):

    for field in ("name", "url", "category"):
        if not isinstance(entry.get(field), str) or not entry[field].strip():
            raise CommandError(f"entry {entry!r}: '{field}' is required")

    if urlparse(entry["url"]).scheme not in ("http", "https"):
        raise CommandError(f"{entry['name']}: url must start with http:// or https://")

    search = entry.get("search")

    if search is not None:

        if not isinstance(search, dict) or not {"url", "param"} <= set(search):
            raise CommandError(f"{entry['name']}: 'search' needs 'url' and 'param'")


class Command(BaseCommand):

    help = "Import live crawl sources from a JSON list."

    def add_arguments(self, parser):
        parser.add_argument("path")
        parser.add_argument(
            "--disable-missing", action="store_true",
            help="disable live sources that are not in the file",
        )

    def handle(self, *args, **options):

        try:
            with open(options["path"], encoding="utf-8") as f:
                entries = json.load(f)

        except (OSError, ValueError) as error:
            raise CommandError(f"cannot read {options['path']}: {error}")

        if not isinstance(entries, list) or not entries:
            raise CommandError("the file must hold a non-empty JSON list")

        for entry in entries:
            validate(entry)

        names = set()

        for entry in entries:

            CrawlSource.objects.update_or_create(
                name=entry["name"].strip(),
                defaults={
                    "url": entry["url"].strip(),
                    "category": entry["category"].strip(),
                    "search": entry.get("search") or {},
                    "kind": "live",
                    "enabled": True,
                },
            )

            names.add(entry["name"].strip())

        if options["disable_missing"]:
            CrawlSource.objects.filter(kind="live").exclude(
                name__in=names
            ).update(enabled=False)

        self.stdout.write(f"imported {len(entries)} live sources")
