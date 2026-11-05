from django.urls import path

from core import auth, views

urlpatterns = [
    path("", views.dashboard),
    path("assets/<path:path>", views.assets),
    path("crawl/start", views.crawl_start),
    path("crawl/jobs", views.crawl_jobs),
    path("crawl/status/<str:job_id>", views.crawl_status),
    path("artifacts", views.artifacts),
    path("artifacts/<str:artifact_id>", views.artifact_detail),
    path("killchain/<str:artifact_id>", views.killchain),
    path("graph/attack-paths", views.attack_paths),
    path("risk-score/<str:artifact_id>", views.risk_score),
    path("evaluation/metrics", views.evaluation_metrics),
    path("evaluation/run", views.evaluation_run),
    path("annotation/samples", views.annotation_samples),
    path("annotation/label", views.annotation_label),
    path("annotation/score", views.annotation_score),
    path("reports/export", views.reports_export),
    path("tor/status", views.tor_status),
    path("auth/me", auth.me),
    path("auth/login", auth.login_view),
    path("auth/register", auth.register_view),
    path("auth/logout", auth.logout_view),
]
