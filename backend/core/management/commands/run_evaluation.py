from django.core.management.base import BaseCommand

from core import evaluation_store
from core.models import CrawlJob


class Command(BaseCommand):
    help = (
        "Retrain the classifiers and evaluate them against the rule-based "
        "baselines; results go to the database (evaluation_record)."
    )

    def add_arguments(self, parser):
        parser.add_argument("--model", default="logreg", choices=["logreg", "rf"])

    def handle(self, *args, **options):

        job = evaluation_store._new_job()

        evaluation_store.run_evaluation(
            job.job_id, options["model"], log=self.stdout.write
        )

        job = CrawlJob.objects.get(pk=job.pk)

        self.stdout.write(f"{job.status}: {job.summary.message}")
