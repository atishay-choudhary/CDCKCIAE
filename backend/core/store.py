"""
Database implementation of the engine's data layer (engine/datastore.py).
"""

import hashlib
import json
from datetime import datetime, timezone

from django.db import transaction

from core.models import (
    AnnotationSample,
    AttackObject,
    AuditEvent,
    CorpusDocument,
    CrawlSource,
    GeneratedFile,
    HistoricalAttack,
    KevEntry,
    LabelledSample,
    NvdRecord,
    StoredReport,
    StoreCache,
    TrainedModel,
)

CHUNK = 2000


class DatabaseStore:

    # the job whose audit events / files are being recorded (set by the
    # backend around a run; None for command-line runs)
    current_job = None

    # ------------------------------------------------------ reference

    def nvd_vulnerabilities(self, recent_only=False):

        rows = NvdRecord.objects.all()

        if recent_only:
            rows = rows.filter(in_recent=True)

        return [
            {"cve": record}
            for record in rows.order_by("pk").values_list("record", flat=True)
            .iterator(chunk_size=CHUNK)
        ]

    def nvd_by_ids(self, ids):

        return {
            pk: record for pk, record in
            NvdRecord.objects.filter(pk__in=list(ids))
            .values_list("pk", "record")
        }

    def kev_entries(self):

        return [
            {"cve_id": k.cve_id, "vendor": k.vendor,
             "product": k.product, "name": k.name}
            for k in KevEntry.objects.all()
        ]

    def mitre_objects(self):

        return list(
            AttackObject.objects.values_list("record", flat=True)
            .iterator(chunk_size=CHUNK)
        )

    def historical_attacks(self):

        return list(
            HistoricalAttack.objects.values_list("record", flat=True)
        )

    # ------------------------------------------- labelled set + models

    def save_labelled(self, task, rows):
        """
        rows: dicts with id, text, split and the label (severity or
        stage); other keys are kept in extra. Replaces the task's set.
        """

        label_key = {"severity": "severity", "stage": "stage"}[task]

        with transaction.atomic():

            LabelledSample.objects.filter(task=task).delete()

            LabelledSample.objects.bulk_create(
                (
                    LabelledSample(
                        task=task,
                        sample_id=str(row["id"]),
                        text=row["text"],
                        label=row[label_key],
                        split=row["split"],
                        extra={
                            k: v for k, v in row.items()
                            if k not in ("id", "text", "split", label_key)
                        },
                    )
                    for row in rows
                ),
                batch_size=CHUNK,
            )

        return len(rows)

    def labelled_split(self, task):

        def part(split):

            rows = list(
                LabelledSample.objects.filter(task=task, split=split)
                .order_by("sample_id").values_list("text", "label")
            )

            return [t for t, _ in rows], [l for _, l in rows]

        X_train, y_train = part("train")

        X_test, y_test = part("test")

        if not X_train:
            raise LookupError(
                f"no labelled data for '{task}' in the database; run "
                "python backend/manage.py build_labelled"
            )

        return X_train, y_train, X_test, y_test

    def save_model(self, task, name, blob, meta):

        TrainedModel.objects.update_or_create(
            task=task, defaults={"name": name, "blob": blob, "meta": meta}
        )

    def load_model(self, task):

        row = TrainedModel.objects.filter(task=task).first()

        return bytes(row.blob) if row else None

    def cache_get(self, key):

        row = StoreCache.objects.filter(key=key).first()

        return row.value if row else None

    def cache_set(self, key, value):

        StoreCache.objects.update_or_create(key=key, defaults={"value": value})

    # ---------------------------------------------- crawling + audit

    def crawl_sources(self, kind="live"):

        return [
            {"name": s.name, "url": s.url, "category": s.category,
             **({"search": s.search} if s.search else {})}
            for s in CrawlSource.objects.filter(kind=kind, enabled=True)
        ]

    def mock_page(self, url):

        row = CrawlSource.objects.filter(kind="mock", url=url).first()

        return row.content if row else None

    def save_document(self, url, text, source_type):

        digest = hashlib.sha1(text.encode("utf-8")).hexdigest()

        CorpusDocument.objects.get_or_create(
            sha1=digest,
            defaults={"url": url, "source_type": source_type, "text": text},
        )

    def documents(self):

        return list(
            CorpusDocument.objects.order_by("collected_at").values(
                "sha1", "url", "source_type", "text"
            )
        )

    def log_event(self, event):

        stamp = event.get("timestamp")

        try:
            when = datetime.fromisoformat(stamp)

        except (TypeError, ValueError):
            when = datetime.now(timezone.utc)

        AuditEvent.objects.create(
            timestamp=when, job=self.current_job, payload=event
        )

    # ----------------------------------------------------- reports

    def annotation_replace(self, task, rows):

        with transaction.atomic():

            AnnotationSample.objects.filter(task=task).delete()

            AnnotationSample.objects.bulk_create([
                AnnotationSample(
                    task=task,
                    sample_id=r["id"],
                    source=r.get("source", "")[:500],
                    source_type=r.get("source_type", ""),
                    text=r["text"],
                    labels={},
                )
                for r in rows
            ])

    def annotation_rows(self, task):

        return [
            {
                "id": s.sample_id, "source": s.source,
                "source_type": s.source_type, "text": s.text, **s.labels,
            }
            for s in AnnotationSample.objects.filter(task=task)
            .order_by("sample_id")
        ]

    def annotation_label(self, task, sample_id, labels):

        sample = AnnotationSample.objects.get(task=task, sample_id=sample_id)

        sample.labels = {**sample.labels, **labels}
        sample.save(update_fields=["labels"])

    def save_report(self, name, data):

        StoredReport.objects.update_or_create(
            name=name, defaults={"data": json.loads(json.dumps(data, default=str))}
        )

    def get_report(self, name):

        row = StoredReport.objects.filter(name=name).first()

        return row.data if row else None

    def latest_file(self, kind, name=None):
        """Newest stored file's bytes for this job (or overall), or None."""

        rows = GeneratedFile.objects.filter(kind=kind)

        if name:
            rows = rows.filter(name=name)

        if self.current_job is not None:
            rows = rows.filter(job=self.current_job)

        row = rows.order_by("-id").first()

        return bytes(row.content) if row else None

    def save_file(self, kind, name, content):

        return GeneratedFile.objects.create(
            kind=kind, name=name, job=self.current_job, content=content
        ).pk
