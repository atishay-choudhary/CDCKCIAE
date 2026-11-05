"""
Gives jobs that have no owner (made before users existed) to one user.

    python manage.py assign_jobs <username>
"""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from core.models import CrawlJob


class Command(BaseCommand):

    help = "Assign all unowned collection jobs to a user."

    def add_arguments(self, parser):
        parser.add_argument("username")

    def handle(self, *args, **options):

        try:
            user = get_user_model().objects.get(username=options["username"])

        except get_user_model().DoesNotExist:
            raise CommandError(f"no user named {options['username']!r}")

        count = CrawlJob.objects.filter(owner__isnull=True).exclude(
            source="evaluation"
        ).update(owner=user)

        self.stdout.write(f"assigned {count} jobs to {user.get_username()}")
