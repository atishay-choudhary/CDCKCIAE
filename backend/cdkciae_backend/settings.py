"""
Settings for the CDKCIAE backend.

Secrets and switches come from the environment, never from source
control (SRS NFR Security):

    CDKCIAE_SECRET_KEY   Django secret key (a dev key is used if unset)
    CDKCIAE_DEBUG        "0" to turn debug off (default "1", local demo)
    CDKCIAE_API_TOKEN    if set, every API call needs
                         "Authorization: Bearer <token>"
    CDKCIAE_DB           path of the SQLite file (default backend/db.sqlite3)

SQLite is used for development. For a larger deployment change DATABASES
to PostgreSQL; the models use only portable fields and indexes.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

PROJECT_ROOT = BASE_DIR.parent

SECRET_KEY = os.environ.get(
    "CDKCIAE_SECRET_KEY", "dev-only-insecure-key-set-CDKCIAE_SECRET_KEY"
)

DEBUG = os.environ.get("CDKCIAE_DEBUG", "1") == "1"

API_TOKEN = os.environ.get("CDKCIAE_API_TOKEN", "")

ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver"]

INSTALLED_APPS = ["core"]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "cdkciae_backend.urls"

TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": []},
}]

WSGI_APPLICATION = "cdkciae_backend.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("CDKCIAE_DB", str(BASE_DIR / "db.sqlite3")),
        # jobs run in a worker thread
        "OPTIONS": {"timeout": 30},
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

USE_TZ = True

TIME_ZONE = "UTC"
