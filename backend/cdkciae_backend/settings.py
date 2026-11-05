"""
Settings for the CDKCIAE backend.

Secrets and switches come from the environment, never from source
control (SRS NFR Security):

    CDKCIAE_SECRET_KEY   Django secret key (a dev key is used if unset)
    CDKCIAE_DEBUG        "0" to turn debug off (default "1", local demo)
    CDKCIAE_API_TOKEN    if set, every API call needs
                         "Authorization: Bearer <token>" or a signed-in session
    CDKCIAE_ALLOW_SIGNUP  "0" to stop visitors creating their own account
                         (default "1"; new accounts are never staff)
    CDKCIAE_REQUIRE_LOGIN "1" to require a signed-in user (create one with
                         `manage.py createsuperuser`)
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

REQUIRE_LOGIN = os.environ.get("CDKCIAE_REQUIRE_LOGIN", "0") == "1"

# anyone who can reach the server may create an ordinary (non-staff) account
ALLOW_SIGNUP = os.environ.get("CDKCIAE_ALLOW_SIGNUP", "1") == "1"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "cdkciae_backend.urls"

TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
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

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = 8 * 3600

USE_TZ = True

TIME_ZONE = "UTC"
