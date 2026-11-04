from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = (
        "Build the labelled severity / kill-chain sets from the reference "
        "tables into labelled_sample (needs sync_reference first)."
    )

    def handle(self, *args, **options):

        from engine.evaluation import dataset_builder

        dataset_builder.main()
