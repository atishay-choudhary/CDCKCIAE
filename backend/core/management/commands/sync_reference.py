import os

from django.core.management.base import BaseCommand

from core import ingest


class Command(BaseCommand):
    help = (
        "Fill the reference tables (NVD, CISA KEV, MITRE ATT&CK, historical "
        "incidents, mock pages, sources).\n"
        "  --pull kev,mitre,nvd   download straight into the database\n"
        "  --from-files           one-off import of files already in datasets/\n"
        "NVD pulls are slow without NVD_API_KEY (rate limit): use "
        "--nvd-years to choose how far back."
    )

    def add_arguments(self, parser):
        parser.add_argument("--pull", default="", help="kev,mitre,nvd")
        parser.add_argument("--nvd-years", type=int, default=2)
        parser.add_argument("--from-files", action="store_true")
        parser.add_argument("--root", default="datasets")

    def handle(self, *args, **options):

        say = self.stdout.write

        pulls = {p for p in options["pull"].split(",") if p}

        root = options["root"]

        if options["from_files"]:
            self._from_files(root, say)

        if "kev" in pulls:
            say(f"KEV: {ingest.ingest_kev(ingest.fetch_kev())} entries")

        if "mitre" in pulls:
            say(f"ATT&CK: {ingest.ingest_mitre(ingest.fetch_mitre())} objects")

        if "nvd" in pulls:

            from datetime import datetime, timedelta, timezone

            key = os.environ.get("NVD_API_KEY")

            end = datetime.now(timezone.utc).replace(tzinfo=None)

            start = end - timedelta(days=365 * options["nvd_years"])

            say(f"NVD: {ingest.ingest_nvd(ingest.fetch_nvd(start, end, key, say))} records")

            say("NVD recent: %d records" % ingest.ingest_nvd(
                ingest.fetch_nvd_recent(key), recent=True
            ))

        ingest.seed_sources(self._mock_pages())

        say("Sources and mock pages are in the database.")

    def _mock_pages(self):

        folder = "mock_sites"

        if not os.path.isdir(folder):
            return {}

        pages = {}

        for name in sorted(os.listdir(folder)):

            if name.endswith(".html"):

                with open(os.path.join(folder, name), "r", encoding="utf-8") as f:
                    pages[name] = f.read()

        return pages

    def _from_files(self, root, say):

        def path(*parts):
            return os.path.join(root, *parts)

        def have(p):
            ok = os.path.exists(p)
            if not ok:
                say(f"  (not found: {p})")
            return ok

        if have(path("cisa", "raw", "known_exploited_vulnerabilities.json")):
            say("KEV: %d entries" % ingest.ingest_kev(
                ingest.load_json(path("cisa", "raw", "known_exploited_vulnerabilities.json"))
                ["vulnerabilities"]
            ))

        # oldest feed first so newer records win
        for name in ("nvdcve-2.0-2024.json", "nvdcve-2.0-2025.json",
                     "nvdcve-2.0-modified.json", "nvdcve-2.0-recent.json"):

            file = path("cves", "raw", name)

            if have(file):
                say("%s: %d records" % (name, ingest.ingest_nvd(
                    ingest.load_json(file)["vulnerabilities"],
                    recent=name.endswith("recent.json"),
                )))

        if have(path("mitre", "raw", "enterprise-attack.json")):
            say("ATT&CK: %d objects" % ingest.ingest_mitre(
                ingest.load_json(path("mitre", "raw", "enterprise-attack.json"))["objects"]
            ))

        if have(path("historical", "historical_attacks.json")):
            say("Historical incidents: %d" % ingest.ingest_historical(
                ingest.load_json(path("historical", "historical_attacks.json"))
            ))
