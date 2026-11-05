"""
Authentication (SRS use case "Authenticate").

Three ways in, checked in this order:
  1. the shared bearer token (CDKCIAE_API_TOKEN), for scripts;
  2. a Django user session (POST /auth/login), for the dashboard;
  3. nothing, when neither CDKCIAE_API_TOKEN nor CDKCIAE_REQUIRE_LOGIN is set
     (local demo).

Each job belongs to the user who started it; a signed-in user sees only
their own jobs (superusers see all). The bearer token, and a server with
no login at all, see everything.

Session requests that change data must carry "X-Requested-With: cdkciae".
Browsers cannot add a custom header cross-site without a CORS preflight,
which this server never grants, so this blocks cross-site request forgery
without CSRF tokens. Sign-in attempts are throttled per user and address.
"""

import hmac
import json
import re

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.cache import cache
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

HEADER = "X-Requested-With"
HEADER_VALUE = "cdkciae"
SAFE = ("GET", "HEAD", "OPTIONS")

USERNAME = re.compile(r"[A-Za-z0-9._-]{3,30}")
MAX_REGISTRATIONS = 10
REGISTER_WINDOW = 3600

MAX_FAILURES = 5
LOCKOUT_SECONDS = 300


def visible_to(request):
    """The user whose jobs may be shown, or None when nothing is filtered."""

    user = request.user

    if user.is_authenticated and not user.is_superuser:
        return user

    return None


def login_required_by_config():
    return bool(settings.API_TOKEN or settings.REQUIRE_LOGIN)


def authorise(request):
    """None when allowed, otherwise the JsonResponse to send."""

    token = settings.API_TOKEN

    if token:
        supplied = request.headers.get("Authorization", "")

        if hmac.compare_digest(supplied, f"Bearer {token}"):
            return None

    if request.user.is_authenticated:

        if request.method not in SAFE and request.headers.get(HEADER) != HEADER_VALUE:
            return JsonResponse({"error": f"missing {HEADER} header"}, status=403)

        return None

    if not login_required_by_config():
        return None

    return JsonResponse({"error": "unauthorized"}, status=401)


def _json_body(request):

    if request.content_type != "application/json":
        return None, JsonResponse(
            {"error": "Content-Type must be application/json"}, status=415
        )

    if request.headers.get(HEADER) != HEADER_VALUE:
        return None, JsonResponse({"error": f"missing {HEADER} header"}, status=403)

    try:
        body = json.loads(request.body or b"{}")

    except ValueError:
        return None, JsonResponse({"error": "invalid JSON"}, status=400)

    return (body if isinstance(body, dict) else {}), None


def _throttle_key(request, username):

    address = request.META.get("REMOTE_ADDR", "")

    return f"login-fail:{address}:{username.lower()[:150]}"


@csrf_exempt
@require_http_methods(["GET"])
def me(request):

    user = request.user

    return JsonResponse({
        "login_required": login_required_by_config(),
        "signup_allowed": bool(settings.ALLOW_SIGNUP),
        "authenticated": user.is_authenticated,
        "username": user.get_username() if user.is_authenticated else "",
        "is_staff": bool(user.is_authenticated and user.is_staff),
    })


@csrf_exempt
@require_http_methods(["POST"])
def login_view(request):

    body, error = _json_body(request)

    if error:
        return error

    username = str(body.get("username", ""))
    password = str(body.get("password", ""))

    key = _throttle_key(request, username)

    if cache.get(key, 0) >= MAX_FAILURES:
        return JsonResponse({"error": "too many attempts, wait a few minutes"}, status=429)

    user = authenticate(request, username=username, password=password)

    if user is None:
        try:
            cache.add(key, 0, LOCKOUT_SECONDS)
            cache.incr(key)

        except ValueError:
            pass

        return JsonResponse({"error": "wrong username or password"}, status=401)

    cache.delete(key)
    login(request, user)

    return JsonResponse({"authenticated": True, "username": user.get_username()})


@csrf_exempt
@require_http_methods(["POST"])
def register_view(request):

    if not settings.ALLOW_SIGNUP:
        return JsonResponse({"error": "sign-up is turned off"}, status=403)

    body, error = _json_body(request)

    if error:
        return error

    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))

    key = f"register:{request.META.get('REMOTE_ADDR', '')}"

    if cache.get(key, 0) >= MAX_REGISTRATIONS:
        return JsonResponse({"error": "too many accounts from this address, try later"}, status=429)

    User = get_user_model()

    if not USERNAME.fullmatch(username):
        return JsonResponse(
            {"error": "user name: 3-30 letters, digits, . _ - only"}, status=400
        )

    if User.objects.filter(username__iexact=username).exists():
        return JsonResponse({"error": "that user name is taken"}, status=409)

    candidate = User(username=username)

    try:
        validate_password(password, candidate)

    except ValidationError as problems:
        return JsonResponse({"error": " ".join(problems.messages)}, status=400)

    user = User.objects.create_user(username, password=password)

    cache.add(key, 0, REGISTER_WINDOW)
    try:
        cache.incr(key)
    except ValueError:
        pass

    login(request, user)

    return JsonResponse({"authenticated": True, "username": user.get_username()}, status=201)


@csrf_exempt
@require_http_methods(["POST"])
def logout_view(request):

    _, error = _json_body(request)

    if error:
        return error

    logout(request)

    return JsonResponse({"authenticated": False})
