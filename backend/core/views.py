"""
REST endpoints (SRS 14.2) and the dashboard page.

Hardening: POST bodies must be application/json (a browser cannot send
that cross-site without a CORS preflight, which blocks cross-site
request forgery against a local server); an optional bearer token
(CDKCIAE_API_TOKEN) or a user session (core.auth) protects every API call; no response exposes crawler
configuration or raw, unredacted text.
"""

import json
from functools import wraps
from pathlib import Path

from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.static import serve as static_serve
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from core import auth, evaluation_store, services
from core.models import (
    Artifact,
    CrawlJob,
    GraphEdge,
    GraphNode,
    PredictedPath,
)

MODES = ("mock", "live")

MAX_KEYWORDS = 20

MAX_KEYWORD_LENGTH = 64


def api(methods):
    """Method check, authentication (core.auth), JSON errors."""

    def decorator(view):

        @csrf_exempt
        @require_http_methods(methods)
        @wraps(view)
        def wrapper(request, *args, **kwargs):

            denied = auth.authorise(request)

            if denied:
                return denied

            return view(request, *args, **kwargs)

        return wrapper

    return decorator


def _jobs(request):
    """Jobs the caller may see (their own, unless superuser or bearer)."""

    owner = auth.visible_to(request)

    queryset = CrawlJob.objects.all()

    return queryset.filter(owner=owner) if owner else queryset


def _artifacts(request):

    owner = auth.visible_to(request)

    queryset = Artifact.objects.all()

    return queryset.filter(job__owner=owner) if owner else queryset


def _stamp(value):
    return value.isoformat(timespec="seconds") if value else None


def _job_summary(job):

    summary = getattr(job, "summary", None)

    return {
        "job_id": job.job_id,
        "mode": job.source,
        "source_mode": summary.source_used if summary else "",
        "keywords": summary.keywords if summary else [],
        "status": job.status,
        "outcome": summary.outcome if summary else "",
        "message": summary.message if summary else "",
        "started_at": _stamp(job.started_at),
        "completed_at": _stamp(job.completed_at),
        "threat_level": summary.threat_level if summary else "",
        "impact_score": summary.impact_score if summary else None,
        "criticality": summary.criticality if summary else "",
    }


def _page(request, queryset):

    try:
        limit = min(int(request.GET.get("limit", 100)), 500)
        offset = max(int(request.GET.get("offset", 0)), 0)

    except ValueError:
        limit, offset = 100, 0

    return queryset.count(), queryset[offset:offset + limit]


# ============================================================
# CRAWL JOBS
# ============================================================

@api(["POST"])
def crawl_start(request):

    if request.content_type != "application/json":
        return JsonResponse(
            {"error": "Content-Type must be application/json"}, status=415
        )

    try:
        body = json.loads(request.body or b"{}")

    except ValueError:
        return JsonResponse({"error": "invalid JSON"}, status=400)

    mode = body.get("mode")

    if mode not in MODES:
        return JsonResponse({"error": "mode must be mock or live"}, status=400)

    keywords = body.get("keywords", [])

    if isinstance(keywords, str):
        keywords = keywords.split(",")

    keywords = [
        k.strip() for k in keywords if isinstance(k, str) and k.strip()
    ]

    if len(keywords) > MAX_KEYWORDS or any(
        len(k) > MAX_KEYWORD_LENGTH for k in keywords
    ):
        return JsonResponse(
            {"error": f"at most {MAX_KEYWORDS} keywords of "
                      f"{MAX_KEYWORD_LENGTH} characters"}, status=400
        )

    if mode == "live" and not keywords:
        return JsonResponse(
            {"error": "live mode needs at least one keyword"}, status=400
        )

    job = services.start_job(
        mode, keywords, allow_fallback=body.get("allow_fallback", True) is True,
        owner=request.user if request.user.is_authenticated else None,
    )

    return JsonResponse(
        {"job_id": job.job_id, "status": job.status}, status=202
    )


@api(["GET"])
def crawl_jobs(request):

    return JsonResponse({
        "jobs": [
            _job_summary(j)
            for j in _jobs(request).exclude(source="evaluation").select_related("summary")[:50]
        ]
    })


@api(["GET"])
def crawl_status(request, job_id):

    job = get_object_or_404(_jobs(request).select_related("summary"), pk=job_id)

    summary = job.summary

    return JsonResponse({
        **_job_summary(job),
        "business_risk": summary.business_risk,
        "enterprise_exposure": (summary.report_data or {}).get("enterprise_exposure", {}),
        "stats": summary.stats,
        "source_report": summary.source_report,
        "job_chain": summary.cyber_kill_chain.get("stages", []),
        "ml_only": summary.cyber_kill_chain.get("ml_only", []),
        "ml_adds_stages": summary.cyber_kill_chain.get("ml_adds_stages"),
        "artifact_count": job.artifacts.count(),
    })


# ============================================================
# ARTIFACTS
# ============================================================

def _ml_stage(artifact):

    mapping = artifact.kill_chain.first()

    return (mapping.stage, mapping.confidence) if mapping else ("", None)


def _artifact_summary(artifact):

    stage, confidence = _ml_stage(artifact)

    score = artifact.risk_scores.first()

    ml = (score.contributing_factors.get("artifact_ml", {}) if score else {})

    return {
        "id": artifact.id,
        "job_id": artifact.job_id,
        "source": artifact.source,
        "source_type": artifact.source_type,
        "collected_at": _stamp(artifact.collected_at),
        "entity_counts": {
            kind: len(values)
            for kind, values in artifact.extracted_entities.items()
            if not kind.startswith("_")
        },
        "extraction": artifact.extracted_entities.get("_extraction", {}),
        "ml_severity": ml.get("severity") or "",
        "ml_severity_confidence": ml.get("confidence"),
        "ml_stage": stage,
        "ml_stage_confidence": confidence,
    }


@api(["GET"])
def artifacts(request):

    queryset = _artifacts(request).prefetch_related("kill_chain", "risk_scores")

    for param, field in (
        ("job", "job_id"),
        ("source", "source__icontains"),
        ("source_type", "source_type"),
        ("stage", "kill_chain__stage"),
        ("severity", "severity"),
        ("since", "collected_at__date__gte"),
    ):

        value = request.GET.get(param)

        if value:
            queryset = queryset.filter(**{field: value})

    total, rows = _page(request, queryset.distinct())

    return JsonResponse({
        "total": total,
        "artifacts": [_artifact_summary(a) for a in rows]
    })


@api(["GET"])
def artifact_detail(request, artifact_id):

    artifact = get_object_or_404(_artifacts(request), pk=artifact_id)

    return JsonResponse({
        **_artifact_summary(artifact),
        "entities": {
            k: v for k, v in artifact.extracted_entities.items()
            if not k.startswith("_")
        },
        "cves": list(
            artifact.cves.values(
                "cve_id", "description", "severity_score",
                "affected_platforms", "exploit_availability"
            )
        ),
        "text": artifact.raw_text[:2000],
        "text_note": "redacted; first 2000 characters",
    })


@api(["GET"])
def killchain(request, artifact_id):

    artifact = get_object_or_404(
        _artifacts(request).select_related("job__summary"), pk=artifact_id
    )

    summary = artifact.job.summary

    return JsonResponse({
        "artifact_id": artifact.id,
        "artifact_stages": [
            {
                "stage": m.stage,
                "confidence": m.confidence,
                "mapping_method": m.mapping_method,
            }
            for m in artifact.kill_chain.all()
        ],
        "job_id": artifact.job_id,
        "job_chain": summary.cyber_kill_chain.get("stages", []),
        "ml_only": summary.cyber_kill_chain.get("ml_only", []),
        "ml_adds_stages": summary.cyber_kill_chain.get("ml_adds_stages"),
    })


# ============================================================
# GRAPH + RISK
# ============================================================

def _empty_graph(job):

    return {
        "job_id": job.job_id if job else None,
        "status": job.status if job else None,
        "outcome": job.summary.outcome if job else "",
        "message": job.summary.message if job else "",
        "nodes": [], "edges": [], "paths": [], "centrality": [],
    }


@api(["GET"])
def attack_paths(request):
    """
    Never 404s for an existing job: a job with no results gets an empty
    graph plus its outcome and message, so the dashboard can explain it.
    """

    jobs = _jobs(request).filter(status="completed").exclude(
        source="evaluation"
    ).select_related("summary")

    if request.GET.get("job"):

        job = get_object_or_404(
            _jobs(request).select_related("summary"), pk=request.GET["job"]
        )

    else:

        job = jobs.filter(artifacts__isnull=False).distinct().first() or jobs.first()

    if job is None:
        return JsonResponse(_empty_graph(None))

    nodes = list(GraphNode.objects.filter(artifact__job=job))

    if not nodes:
        return JsonResponse(_empty_graph(job))

    edges = GraphEdge.objects.filter(source_node__in=nodes)

    path_ids = {
        step.path_id for node in nodes for step in node.path_steps.all()
    }

    paths = []

    for path in PredictedPath.objects.filter(pk__in=path_ids).order_by(
        "-likelihood_score"
    ):

        steps = path.steps.select_related("node").order_by("sequence_order")

        paths.append({
            "path_id": path.path_id,
            "entry": steps[0].node.asset_type,
            "path": [s.node.asset_type for s in steps],
            "likelihood": path.likelihood_score,
            "algorithm": path.algorithm_used,
        })

    return JsonResponse({
        **_empty_graph(job),
        "nodes": [
            {"node_id": n.node_id, "asset_type": n.asset_type,
             "centrality_score": n.centrality_score}
            for n in nodes
        ],
        "edges": [
            {"source": e.source_node.asset_type,
             "target": e.target_node.asset_type,
             "weight": e.edge_weight}
            for e in edges.select_related("source_node", "target_node")
        ],
        "paths": paths,
        "centrality": sorted(
            (
                {"stage": n.asset_type, "centrality": n.centrality_score}
                for n in nodes
            ),
            key=lambda c: -c["centrality"]
        ),
    })


@api(["GET"])
def risk_score(request, artifact_id):

    artifact = get_object_or_404(_artifacts(request), pk=artifact_id)

    score = artifact.risk_scores.order_by("-scored_at").first()

    factors = score.contributing_factors if score else {}

    return JsonResponse({
        "artifact_id": artifact.id,
        "job_id": artifact.job_id,
        "scope": factors.get("scope", "job"),
        "scope_note": "The CVSS/FAIR impact score is computed for the whole "
                      "collection; the artifact's own model prediction is "
                      "shown separately.",
        "impact_score": score.impact_score if score else None,
        "criticality": factors.get("criticality"),
        "contributing_factors": factors,
        "scored_at": _stamp(score.scored_at) if score else None,
        "artifact_ml": factors.get("artifact_ml", {}),
    })


# ============================================================
# EVALUATION, REPORTS, TOR, DASHBOARD
# ============================================================

@api(["GET"])
def evaluation_metrics(request):
    """
    The latest evaluation run, from the database. Nothing is read from data files.
    "state" tells the dashboard whether there is a run,
    one in progress, or none yet.
    """

    running = CrawlJob.objects.filter(
        source="evaluation", status__in=("queued", "running")
    ).first()

    job = evaluation_store.latest()

    body = {
        "state": "none",
        "job_id": None,
        "generated_at": None,
        "model": None,
        "message": "",
        "classifier": None,
        "paths": None,
        "ner": None,
        "records": {},
    }

    if job:

        data = job.summary.report_data

        body.update({
            "state": "ready",
            "job_id": job.job_id,
            "generated_at": _stamp(job.completed_at),
            "model": data.get("model"),
            "message": job.summary.message,
            "classifier": data.get("classifier"),
            "paths": data.get("paths"),
            "ner": data.get("ner"),
            "records": services.evaluation_from_records(),
        })

    if running:
        body.update({"state": "running", "job_id": running.job_id})

    return JsonResponse(body)


@api(["POST"])
def evaluation_run(request):

    job = evaluation_store.start()

    return JsonResponse({"job_id": job.job_id, "status": job.status}, status=202)


# ============================================================
# ANNOTATION (FR-8.1): label dark-web snippets, score the models on them
# ============================================================

def _annotation_task():

    from engine.evaluation import darkweb_validation

    return darkweb_validation


@api(["GET"])
def annotation_samples(request):
    """Sampled snippets with their labels. Source URLs are not exposed."""

    from engine import datastore

    module = _annotation_task()

    rows = datastore.annotation_rows(module.TASK)

    return JsonResponse({
        "severity_labels": module.TASK_LABELS["severity"],
        "stage_labels": module.TASK_LABELS["stage"],
        "samples": [
            {
                "id": r["id"],
                "text": r["text"],
                "severity": r.get("severity", ""),
                "stage": r.get("stage", ""),
            }
            for r in rows
        ],
    })


@api(["POST"])
def annotation_label(request):

    from engine import datastore

    if request.content_type != "application/json":
        return JsonResponse(
            {"error": "Content-Type must be application/json"}, status=415
        )

    try:
        body = json.loads(request.body or b"{}")

    except ValueError:
        return JsonResponse({"error": "invalid JSON"}, status=400)

    module = _annotation_task()

    labels = {}

    for field in ("severity", "stage"):

        value = body.get(field)

        if value is None:
            continue

        if value != "" and value not in module.TASK_LABELS[field]:
            return JsonResponse({"error": f"invalid {field}"}, status=400)

        labels[field] = value

    try:
        datastore.annotation_label(module.TASK, str(body.get("id", "")), labels)

    except Exception:
        return JsonResponse({"error": "unknown sample"}, status=404)

    return JsonResponse({"id": body["id"], **labels})


@api(["GET"])
def annotation_score(request):

    try:
        reports = _annotation_task().score_labelled()

    except FileNotFoundError:
        return JsonResponse(
            {"error": "no trained model yet: run manage.py bootstrap"},
            status=409
        )

    return JsonResponse({"reports": reports})


@api(["POST"])
def reports_export(request):

    if request.content_type != "application/json":
        return JsonResponse(
            {"error": "Content-Type must be application/json"}, status=415
        )

    try:
        body = json.loads(request.body or b"{}")

    except ValueError:
        return JsonResponse({"error": "invalid JSON"}, status=400)

    if body.get("artifact_id"):

        artifact = get_object_or_404(
            _artifacts(request).select_related("job__summary"),
            pk=body["artifact_id"]
        )

        try:
            pdf = services.export_artifact_pdf(artifact)

        except ValueError as e:
            return JsonResponse({"error": str(e)}, status=409)

        response = HttpResponse(pdf, content_type="application/pdf")
        response["Content-Disposition"] = (
            f'attachment; filename="cdkciae_artifact_{artifact.id}.pdf"'
        )

        return response

    job = get_object_or_404(
        _jobs(request).select_related("summary"), pk=body.get("job_id")
    )

    try:
        pdf = services.export_pdf(job)

    except ValueError as e:
        return JsonResponse({"error": str(e)}, status=409)

    response = HttpResponse(pdf, content_type="application/pdf")

    response["Content-Disposition"] = (
        f'attachment; filename="cdkciae_{job.job_id}.pdf"'
    )

    return response


@api(["GET"])
def tor_status(request):

    return JsonResponse(services.tor_status())


DIST = Path(__file__).resolve().parent / "frontend_dist"

CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; "
    "script-src 'self'; frame-ancestors 'none'"
)


def dashboard(request):
    """The React single-page app (built bundle in core/frontend_dist)."""

    index = DIST / "index.html"

    if not index.exists():
        return HttpResponse(
            "The dashboard bundle is missing. Build it with "
            "'cd frontend && npm install && npm run build'.",
            status=503, content_type="text/plain"
        )

    response = HttpResponse(index.read_text(encoding="utf-8"))

    response["Content-Security-Policy"] = CSP

    return response


def assets(request, path):

    return static_serve(request, path, document_root=DIST)
