"""
Evaluation (FR-8.x, UC-6/UC-7) stored in the database.

One "evaluation" CrawlJob holds the latest run:
  * every held-out labelled row is an Artifact (source_type "labelled");
  * every prediction is an EvaluationRecord (ground_truth_label,
    predicted_label, module = "<system>:<task>", e.g. "classifier:stage",
    "baseline:severity", "tuned_baseline:stage");
  * the aggregate report (precision/recall/F1, confusion matrices, CV,
    path-prediction accuracy) is kept in the job summary's report_data.

Everything is read from and written to the database.
"""

from django.db import transaction
from django.utils import timezone

from engine import datastore
from core.models import Artifact, CrawlJob, EvaluationRecord, JobSummary

SYSTEMS = ("classifier", "baseline", "tuned_baseline")

CHUNK = 2000


def _new_job():

    job = CrawlJob.objects.create(source="evaluation")

    JobSummary.objects.create(job=job, source_used="evaluation")

    return job


def _path_report():
    """
    Runs the engine's own path evaluation (python -m
    engine.evaluation.path_evaluation), so the numbers are exactly the
    command-line ones, and returns its report.
    """

    import contextlib
    import io

    from engine.evaluation import path_evaluation as pe

    with contextlib.redirect_stdout(io.StringIO()):
        return pe.run()


def run_evaluation(job_id, model="logreg", log=lambda message: None):
    """
    Retrains the classifiers (UC-6, the trained_model rows are refreshed) and
    evaluates them against the rule-based baselines on the fixed
    held-out split. Slow (minutes): run it in the background.
    """

    from engine.evaluation import evaluate as ev
    from engine.ml.classifier import TASKS, load_split, predict

    job = CrawlJob.objects.get(pk=job_id)

    summary = job.summary

    job.status = "running"

    job.save(update_fields=["status"])

    report = {"classifier": {}, "paths": None, "ner": None}

    try:

        records, artifacts = [], []

        for task in TASKS:

            log(f"{task}: training and scoring")

            report["classifier"][task] = ev.evaluate_task(task, model)

            _, _, X_test, y_test = load_split(task)

            predictions = {
                "classifier": [label for label, _ in predict(task, X_test)],
                "baseline": [ev.BASELINES[task](t) for t in X_test],
            }

            tuned = ev.tuned_baseline(task)

            predictions["tuned_baseline"] = [tuned(t) for t in X_test]

            for i, (text, truth) in enumerate(zip(X_test, y_test)):

                artifact = Artifact(
                    job=job, source=f"labelled:{task}:{i}",
                    source_type="labelled", raw_text=text[:2000]
                )

                artifacts.append(artifact)

                for system in SYSTEMS:

                    records.append(EvaluationRecord(
                        artifact=artifact,
                        ground_truth_label=str(truth),
                        predicted_label=str(predictions[system][i]),
                        module=f"{system}:{task}",
                    ))

        try:

            log("attack-path prediction")

            report["paths"] = _path_report()

        except Exception as e:      # data not downloaded, etc.

            log(f"path evaluation skipped: {type(e).__name__}: {e}")

        report["ner"] = datastore.get_report("ner_evaluation")

        with transaction.atomic():

            for old in CrawlJob.objects.filter(source="evaluation").exclude(
                pk=job.pk
            ):
                old.delete()

            Artifact.objects.bulk_create(artifacts, batch_size=CHUNK)

            EvaluationRecord.objects.bulk_create(records, batch_size=CHUNK)

        summary.report_data = {"model": model, **report}

        summary.outcome = "results"

        summary.message = (
            f"{len(artifacts)} held-out rows, {len(records)} predictions"
        )

        job.status = "completed"

    except Exception as e:

        job.status = "failed"

        summary.outcome = "failed"

        summary.message = f"{type(e).__name__}: {e}"

    job.completed_at = timezone.now()

    job.save()

    summary.save()

    return job


def latest():
    """(evaluation job or None)"""

    return (
        CrawlJob.objects.filter(source="evaluation", status="completed")
        .select_related("summary").order_by("-started_at").first()
    )


def start(model="logreg"):
    """
    Create the evaluation job and run it in the background. If one is
    already queued or running, that job is returned instead.
    """

    import threading

    from core import services

    running = CrawlJob.objects.filter(
        source="evaluation", status__in=("queued", "running")
    ).first()

    if running:
        return running

    job = _new_job()

    def work():

        from django.db import close_old_connections

        close_old_connections()

        try:

            with services._RUN_LOCK:
                run_evaluation(job.job_id, model)

        finally:

            close_old_connections()

    threading.Thread(target=work, daemon=True).start()

    return job
