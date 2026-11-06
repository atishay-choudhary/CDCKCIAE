"""
Runs engine pipelines as background jobs and persists their output into
the documented tables (see core/models.py).

The engine stays Django-free: this module only imports and calls it.
One job runs at a time (the engine keeps module-level caches and writes
shared files); the rest wait as "queued".

A job that reaches its sources but finds nothing ends as status
"completed" with outcome "no_matches" and the per-source audit rows, so
the dashboard can say what happened instead of showing empty panels.
"""

import io
import json
import threading


from django.db import close_old_connections, transaction
from django.utils import timezone

from engine import datastore

from core.models import (
    Artifact,
    AuditEvent,
    CorpusDocument,
    CrawlJob,
    CveReference,
    EvaluationRecord,
    GraphEdge,
    GraphNode,
    JobSummary,
    KevEntry,
    KillchainMapping,
    PredictedPath,
    PredictedPathNode,
    RiskScore,
)

_RUN_LOCK = threading.Lock()

def _plain(value):
    """JSON-safe copy (numpy floats / strings become plain Python)."""

    return json.loads(json.dumps(value, default=str))


# ============================================================
# JOB LIFECYCLE
# ============================================================

def start_job(mode, keywords, allow_fallback=True, owner=None):

    job = CrawlJob.objects.create(source=mode, owner=owner)

    JobSummary.objects.create(
        job=job, keywords=keywords, allow_fallback=allow_fallback
    )

    threading.Thread(target=run_job, args=(job.job_id,), daemon=True).start()

    return job


def run_job(job_id):

    close_old_connections()

    try:

        with _RUN_LOCK:

            job = CrawlJob.objects.get(pk=job_id)

            summary = job.summary

            job.status = "running"

            job.save(update_fields=["status"])

            datastore.get().current_job = job

            try:

                output, summary.source_used, summary.outcome, \
                    summary.message = _collect(job, summary)

                summary.source_report = _source_report(job)

                if output is not None:

                    with transaction.atomic():
                        _persist(job, summary, output)

                job.status = "completed"

            except Exception as e:

                job.status = "failed"

                summary.outcome = "failed"

                summary.message = f"{type(e).__name__}: {e}"

                summary.source_report = _source_report(job)

            datastore.get().current_job = None

            job.completed_at = timezone.now()

            job.save()

            summary.save()

    finally:

        close_old_connections()


# ============================================================
# COLLECT (live with fallback, or mock)
# ============================================================

def _collect(job, summary):
    """
    Returns (pipeline output or None, source actually used, outcome, note).
    """

    from engine.pipeline import run_pipeline

    if job.source == "mock":
        return run_pipeline(), "mock", "results", ""

    from engine.crawlers.darkweb_live_crawler import log_event
    from engine.crawlers.tor_session import (
        create_tor_session,
        test_tor_connection
    )
    from engine.pipeline_DW import run_darkweb_pipeline

    tor = test_tor_connection(create_tor_session())

    if tor["status"]:

        output = run_darkweb_pipeline(summary.keywords)

        if output.get("status", "ok") == "ok":
            return output, "live", "results", ""

        if output.get("status") == "no_matches":
            return (
                None, "live", "no_matches",
                "Tor works and the sources answered, but no page contained "
                "any of the keywords. See the per-source table."
            )

        reason = "No configured dark web source could be reached."

    else:
        reason = "Tor connectivity failed: " + tor["message"]

    log_event({"mode": "mock-fallback", "reason": reason,
               "enabled": summary.allow_fallback})

    if not summary.allow_fallback:
        raise RuntimeError(reason + " (fallback disabled)")

    return (
        run_pipeline(),
        "mock",
        "fallback",
        "Fallback to the mock corpus - NOT live data. " + reason
    )


def _source_report(job):
    """
    Per-source outcome of this run, from its audit_event rows (FR-1.5).
    No URLs are returned: the API does not expose crawler internals.
    """

    events = [e.payload for e in AuditEvent.objects.filter(job=job)]

    return [
        {
            "source": event.get("source"),
            "keyword": event.get("keyword"),
            "status": event.get("status") or event.get("mode"),
            "http_status": event.get("http_status"),
            "attempts": event.get("attempts"),
            "error": event.get("error") or event.get("reason"),
            "matches": event.get("matches", []),
        }
        for event in events
        if event.get("mode") in ("live", "mock-fallback")
    ][-200:]


# ============================================================
# CVE REFERENCES
# ============================================================

def _lookup_cves(cve_ids):
    """
    cve_id -> reference fields, from the cve_reference / kev_entry tables
    (loaded by `manage.py sync_reference`). Unknown ids get an empty
    reference instead of being dropped.
    """

    wanted = set(cve_ids)

    known = {
        c.cve_id: {
            "description": c.description,
            "severity_score": c.severity_score,
            "affected_platforms": c.affected_platforms,
            "exploit_availability": c.exploit_availability,
        }
        for c in CveReference.objects.filter(pk__in=wanted)
    }

    missing = wanted - set(known)

    kev = {
        k.cve_id: f"{k.vendor} {k.product}".strip()
        for k in KevEntry.objects.filter(pk__in=missing)
    }

    return {
        **known,
        **{
            cve_id: {
                "affected_platforms": kev.get(cve_id, ""),
                "exploit_availability": cve_id in kev,
            }
            for cve_id in missing
        },
    }


def _link_cves(artifacts):

    wanted = {
        a: [c for c in a.extracted_entities.get("cves", [])
            if isinstance(c, str)]
        for a in artifacts
    }

    ids = {c for cves in wanted.values() for c in cves}

    if not ids:
        return

    details = _lookup_cves(ids)

    existing = set(
        CveReference.objects.filter(pk__in=ids).values_list("pk", flat=True)
    )

    CveReference.objects.bulk_create([
        CveReference(cve_id=cve_id, **details[cve_id])
        for cve_id in ids - existing
    ])

    for artifact, cves in wanted.items():
        artifact.cves.add(*cves)


# ============================================================
# ATTACK GRAPH
# ============================================================

def _persist_graph(job, artifacts, prediction):
    """
    GRAPH_NODE / GRAPH_EDGE / PREDICTED_PATH / PREDICTED_PATH_NODE.

    Nodes are kill-chain stages. GRAPH_NODE needs an artifact: the
    node is attached to an artifact the model assigned to that stage,
    otherwise to the job's first artifact. An edge's weight is the best
    likelihood among the predicted paths that use it.
    """

    if not artifacts:
        return

    by_stage = {}

    for artifact in artifacts:

        stage = getattr(artifact, "_ml_stage", "")

        if stage:
            by_stage.setdefault(stage, artifact)

    centrality = {c["stage"]: c for c in prediction["centrality"]}

    paths = [
        (
            item["path"] if isinstance(item["path"], list)
            else item["path"].split(" -> "),
            item["likelihood"]
        )
        for item in prediction["paths"]
    ]

    stages = list(dict.fromkeys(
        [s for path, _ in paths for s in path] + list(centrality)
    ))

    nodes = {
        stage: GraphNode(
            node_id=f"{job.job_id}:{stage}"[:64],
            artifact=by_stage.get(stage, artifacts[0]),
            asset_type=stage,
            centrality_score=centrality.get(stage, {}).get("betweenness", 0.0)
        )
        for stage in stages
    }

    GraphNode.objects.bulk_create(nodes.values())

    edge_weight = {}

    for path, likelihood in paths:

        for a, b in zip(path, path[1:]):
            edge_weight[(a, b)] = max(edge_weight.get((a, b), 0.0), likelihood)

    GraphEdge.objects.bulk_create([
        GraphEdge(
            source_node=nodes[a], target_node=nodes[b], edge_weight=weight
        )
        for (a, b), weight in edge_weight.items()
    ])

    for path, likelihood in paths:

        record = PredictedPath.objects.create(
            likelihood_score=likelihood,
            algorithm_used=prediction["transition_source"]
        )

        PredictedPathNode.objects.bulk_create([
            PredictedPathNode(path=record, node=nodes[s], sequence_order=i)
            for i, s in enumerate(path)
        ])


# ============================================================
# PERSIST
# ============================================================

def _page_text(url):
    """Redacted page text for a source URL, from corpus_document."""

    doc = CorpusDocument.objects.filter(url=url).order_by("-collected_at").first()

    return doc.text[:20000] if doc else ""


KILL_CHAIN_ORDER = [
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
    "Installation", "Command and Control", "Actions on Objectives",
]


def _ordered_stages(chain):
    """Observed kill-chain stages in kill-chain order."""

    found = {s["stage"] for s in chain.get("stages", [])}

    return [s for s in KILL_CHAIN_ORDER if s in found]


def _executive_summary(output, cvss, chain):
    """A factual two-sentence summary for the PDF."""

    stages = _ordered_stages(chain)

    seen = (
        "Kill-chain stages observed: " + ", ".join(stages) + "."
        if stages else "No kill-chain stage could be assigned."
    )

    return (
        f"The collection produced {len(output['signals'])} signals and an "
        f"overall threat level of {output['threat_level']}. {seen} "
        f"The CVSS v3.1 environmental impact score is "
        f"{cvss['impact_score']:.1f} out of 10 ({cvss['criticality']})."
    )


def _persist(job, summary, output):

    records = output["artifact_records"]

    assessment = output["threat_assessment"]

    documents = assessment.get("documents", [])

    if len(documents) != len(records):
        documents = [{}] * len(records)

    artifacts = []

    for record, document in zip(records, documents):

        artifact = Artifact(
            job=job,
            source=record["source"],
            source_type=record["source_type"],
            severity=document.get("severity") or None,
            raw_text=_page_text(record["source"]),
            extracted_entities={
                **_plain(record["entities"]),
                # regex-vs-NER comparison (UC-2); "_" keys are not entities
                "_extraction": {
                    "regex": record.get("regex_count"),
                    "ner": record.get("ner_count"),
                    "duplicates_removed": record.get("duplicates_removed"),
                    "regex_entities": _plain(record.get("regex_entities")),
                    "ner_entities": _plain(record.get("ner_entities")),
                },
            },
        )

        artifact._ml = document

        artifact._ml_stage = document.get("kill_chain_stage", "")

        artifacts.append(artifact)

    Artifact.objects.bulk_create(artifacts)

    cvss = output["cvss_impact"]

    chain = output["cyber_kill_chain"]

    KillchainMapping.objects.bulk_create([
        KillchainMapping(
            artifact=a,
            stage=a._ml_stage,
            confidence=a._ml.get("kill_chain_confidence"),
            mapping_method="ML"
        )
        for a in artifacts if a._ml_stage
    ])

    # The CVSS environmental score is computed for the whole collection,
    # so every artifact carries it; its own model prediction is a factor.
    RiskScore.objects.bulk_create([
        RiskScore(
            artifact=a,
            impact_score=cvss["impact_score"],
            contributing_factors=_plain({
                "scope": "job",
                "criticality": cvss["criticality"],
                "scenarios": cvss["scenarios"],
                "factors": cvss["factors"],
                "artifact_ml": {
                    "severity": a._ml.get("severity"),
                    "confidence": a._ml.get("severity_confidence"),
                },
            })
        )
        for a in artifacts
    ])

    _link_cves(artifacts)

    _persist_graph(job, artifacts, output["path_prediction"])

    summary.threat_level = output["threat_level"]
    summary.impact_score = cvss["impact_score"]
    summary.criticality = cvss["criticality"]
    summary.business_risk = _plain(output["business_risk"])
    summary.cyber_kill_chain = _plain(chain)
    summary.stats = {
        "signals": len(output["signals"]),
        "correlations": len(output["correlations"]),
        "artifacts": len(artifacts),
        "threat_level_baseline": assessment.get("threat_level_baseline"),
        "threat_level_ml": assessment.get("threat_level_ml"),
        "threat_method": assessment.get("method"),
    }
    summary.report_data = _plain({
        "threat_level": output["threat_level"],
        "kill_chain_stages": _ordered_stages(chain),
        "executive_summary": _executive_summary(output, cvss, chain),
        "signals": output["signals"],
        "important_terms": output.get("important_terms", []),
        "enriched_iocs": output.get("enriched_iocs", []),
        "impact_analysis": output.get("impact_analysis", {}),
        "predicted_paths": output.get("path_prediction", {}),
        "propagation_summary": output.get("propagation_summary", []),
        "consequence_summary": output.get("consequence_summary", []),
        "business_risk": output["business_risk"],
        "asset_summary": output.get("asset_summary", []),
        "enterprise_exposure": output.get("enterprise_exposure", {}),
    })


# ============================================================
# EVALUATION RECORDS (module: classifier / path)
# ============================================================

def record_evaluation(artifact, ground_truth, predicted, module):

    return EvaluationRecord.objects.create(
        artifact=artifact,
        ground_truth_label=ground_truth,
        predicted_label=predicted,
        module=module
    )


def evaluation_from_records():
    """Precision / recall / F1 / confusion matrix per module."""

    report = {}

    modules = (
        EvaluationRecord.objects.order_by().values_list("module", flat=True)
        .distinct()
    )

    for module in sorted(modules):

        rows = list(
            EvaluationRecord.objects.filter(module=module)
            .values_list("ground_truth_label", "predicted_label")
        )

        labels = sorted({l for pair in rows for l in pair})

        matrix = {t: {p: 0 for p in labels} for t in labels}

        for truth, predicted in rows:
            matrix[truth][predicted] += 1

        per_class = {}

        for label in labels:

            tp = matrix[label][label]

            fp = sum(matrix[t][label] for t in labels) - tp

            fn = sum(matrix[label].values()) - tp

            precision = tp / (tp + fp) if tp + fp else 0.0

            recall = tp / (tp + fn) if tp + fn else 0.0

            per_class[label] = {
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(
                    2 * precision * recall / (precision + recall), 4
                ) if precision + recall else 0.0,
                "support": tp + fn,
            }

        report[module] = {
            "records": len(rows),
            "accuracy": round(
                sum(matrix[l][l] for l in labels) / len(rows), 4
            ),
            "per_class": per_class,
            "confusion_matrix": {"labels": labels, "matrix": matrix},
        }

    return report


# ============================================================
# TOR (live deployment)
# ============================================================

def tor_status():
    """
    Is the Tor client reachable, and where is it expected? Cheap: a TCP
    connect to the SOCKS port. The routing check (a request through Tor)
    is slower and is made only when a live job starts.
    """

    from engine.crawlers import tor_session

    host, port = tor_session.TOR_HOST, tor_session.TOR_PORT

    listening = tor_session.proxy_listening(host, port, timeout=2)

    return {
        "host": host,
        "port": port,
        "proxy_listening": listening,
        "message": (
            "Tor SOCKS proxy is accepting connections."
            if listening else
            f"Nothing is listening on {host}:{port}. Start Tor, or set "
            "CDKCIAE_TOR_HOST / CDKCIAE_TOR_PORT."
        ),
    }


# ============================================================
# PDF EXPORT (FR-9.5)
# ============================================================

def _artifact_report_data(artifact):
    """Report data for one artifact (UC-8); risk figures stay job-level."""

    from engine.evaluation.corpus import mask_email

    job_data = dict(artifact.job.summary.report_data or {})

    if not job_data:
        raise ValueError("this job has no results to report")

    ml = (artifact.risk_scores.first().contributing_factors or {}).get(
        "artifact_ml", {}
    ) if artifact.risk_scores.exists() else {}

    stages = [m.stage for m in artifact.kill_chain.all()]

    signals = [
        {**s, "value": mask_email(str(s.get("value", "")))}
        for s in job_data.get("signals", [])
        if s.get("source") == artifact.source
    ]

    counts = {
        kind: len(values)
        for kind, values in artifact.extracted_entities.items()
        if not kind.startswith("_") and values
    }

    found = ", ".join(f"{n} {k}" for k, n in counts.items()) or "no entities"

    summary = (
        f"Artifact {artifact.source} ({artifact.source_type}), collected "
        f"{artifact.collected_at:%Y-%m-%d %H:%M}. Model severity: "
        f"{artifact.severity or 'not assigned'}"
        + (f" (confidence {ml['confidence']:.2f})" if ml.get("confidence") else "")
        + f". Kill-chain stage: {', '.join(stages) or 'not assigned'}. "
        f"Extracted {found}; {len(signals)} signals. Impact and risk "
        f"figures below describe the whole collection, not this artifact alone."
    )

    return {
        "executive_summary": summary,
        "threat_level": artifact.severity or "UNKNOWN",
        "kill_chain_stages": stages,
        "signals": signals,
        "impact_analysis": job_data.get("impact_analysis", {}),
        "business_risk": job_data.get("business_risk", {}),
        "enterprise_exposure": job_data.get("enterprise_exposure", {}),
    }


def export_artifact_pdf(artifact):
    """PDF bytes for a single artifact, stored with its job's files."""

    from engine.reports.report_generator import generate_pdf_report

    data = _artifact_report_data(artifact)

    buffer = io.BytesIO()

    generate_pdf_report(data, output=buffer)

    pdf = buffer.getvalue()

    store = datastore.get()
    store.current_job = artifact.job
    store.save_file("pdf", f"artifact_{artifact.id}.pdf", pdf)
    store.current_job = None

    return pdf


def export_pdf(job):
    """PDF bytes for a finished job, from the stored report data."""

    from engine.reports.report_generator import generate_pdf_report

    data = dict(job.summary.report_data)

    if not data:
        raise ValueError("this job has no results to report")

    buffer = io.BytesIO()

    store = datastore.get()
    store.current_job = job

    try:
        generate_pdf_report(data, output=buffer)

    finally:
        store.current_job = None

    pdf = buffer.getvalue()

    store.current_job = job
    store.save_file("pdf", f"report_{job.job_id}.pdf", pdf)
    store.current_job = None

    return pdf
