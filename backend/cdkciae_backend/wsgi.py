import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

os.chdir(ROOT)

sys.path[:0] = [str(ROOT), str(ROOT / "backend")]

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cdkciae_backend.settings")

from django.core.wsgi import get_wsgi_application  # noqa: E402

application = get_wsgi_application()
