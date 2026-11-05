from django.core.management import call_command
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = (
        "Fill an empty database in one go: reference data (sync_reference), "
        "labelled sets (build_labelled) and the trained classifiers. "
        "Pass the same options as sync_reference (e.g. --pull kev,mitre,nvd "
        "or --from-files)."
    )

    def add_arguments(self, parser):
        parser.add_argument("--pull", default="")
        parser.add_argument("--nvd-years", type=int, default=2)
        parser.add_argument("--from-files", action="store_true")
        parser.add_argument("--root", default="datasets")
        parser.add_argument("--model", default="logreg", choices=["logreg", "rf", "svm", "xgboost"])

    def handle(self, *args, **options):

        sync = {k: options[k] for k in ("pull", "nvd_years", "from_files", "root")}

        call_command("sync_reference", **sync)
        call_command("build_labelled")

        from engine.ml.classifier import TASKS, train

        for task in TASKS:
            train(task, options["model"])
            self.stdout.write(f"[+] trained {task} model -> database")
