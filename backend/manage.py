#!/usr/bin/env python
"""
Django entry point for the CDKCIAE backend (O7).

Run from anywhere; the working directory is switched to the project
root (the engine itself keeps no data files: everything is in the
database):

    python backend/manage.py migrate
    python backend/manage.py runserver --noreload
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():

    os.chdir(ROOT)

    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cdkciae_backend.settings")

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
