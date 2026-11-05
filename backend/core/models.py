"""
Persistence, following the System Design ER diagram (Figure 3) and SRS
section 15.1 exactly.

Tables (db_table) and columns are the documented ones:

    crawl_job            job_id PK, source, status, started_at, completed_at
    artifact             id PK, job_id FK, source, raw_text,
                         extracted_entities, collected_at, source_type
    killchain_mapping    id PK, artifact_id FK, stage, confidence,
                         mapping_method
    risk_score           id PK, artifact_id FK, impact_score,
                         contributing_factors, scored_at
    cve_reference        cve_id PK, description, severity_score,
                         affected_platforms, exploit_availability
    graph_node           node_id PK, artifact_id FK, asset_type,
                         centrality_score
    graph_edge           edge_id PK, source_node_id FK, target_node_id FK,
                         edge_weight
    predicted_path       path_id PK, likelihood_score, algorithm_used
    predicted_path_node  path_id FK, node_id FK, sequence_order
    evaluation_record    record_id PK, artifact_id FK, ground_truth_label,
                         predicted_label, module

Artifact <-> CVE_REFERENCE is many-to-many (junction table
artifact_cve_reference). Primary keys are strings, as in the diagram.

crawl_job also has an extension column, owner_id (the user who started it).

The only table that is NOT in the design is job_summary (one row per
crawl job). The documented CRAWL_JOB has no place for the keywords, the
run message, the threat level or the job-level kill-chain summary, so
they live there instead of being added to a documented table.

Artifact text is stored redacted (engine.evaluation.corpus.redact).

Data stores (System Design DFD D1, D3, D4, D6, D7). The ER diagram only
covers the core entities, but the DFD also shows the stores the engine
reads and writes. They are database tables here, so no JSON/CSV/joblib
file is needed at run time. They are extensions, listed after the
documented tables:

    D1 raw corpus      corpus_document, crawl_source (mock pages)
    D3 reference       nvd_record, kev_entry, attack_object,
                       historical_attack (+ cve_reference above)
    D4 model store     trained_model
    D6 labelled set    labelled_sample
    D7 reports         generated_file, stored_report
    audit (FR-1.5)     audit_event
    caches             store_cache
"""

import uuid

from django.conf import settings
from django.db import models


def new_id(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def job_id():
    return new_id("job")


def artifact_id():
    return new_id("art")


def mapping_id():
    return new_id("kcm")


def score_id():
    return new_id("rsk")


def node_id():
    return new_id("nod")


def edge_id():
    return new_id("edg")


def path_id():
    return new_id("pth")


def record_id():
    return new_id("evr")


class CrawlJob(models.Model):

    STATUSES = [
        ("queued", "queued"),
        ("running", "running"),
        ("completed", "completed"),
        ("failed", "failed"),
    ]

    job_id = models.CharField(
        primary_key=True, max_length=32, default=job_id, editable=False
    )
    source = models.CharField(max_length=16)          # mock / live
    status = models.CharField(max_length=16, choices=STATUSES, default="queued")
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    # extension column: who started the job (dashboard users see only theirs)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="jobs", db_column="owner_id"
    )

    class Meta:
        db_table = "crawl_job"
        ordering = ["-started_at"]


class JobSummary(models.Model):
    """Extension table (not in the design): run details of one job."""

    job = models.OneToOneField(
        CrawlJob, on_delete=models.CASCADE, related_name="summary",
        primary_key=True, db_column="job_id"
    )
    source_used = models.CharField(max_length=16, blank=True)
    keywords = models.JSONField(default=list)
    allow_fallback = models.BooleanField(default=True)
    # results | no_matches | fallback | failed
    outcome = models.CharField(max_length=16, blank=True)
    message = models.TextField(blank=True)
    source_report = models.JSONField(default=list)   # per-source audit rows
    threat_level = models.CharField(max_length=10, blank=True)
    impact_score = models.FloatField(null=True)
    criticality = models.CharField(max_length=10, blank=True)
    business_risk = models.JSONField(default=dict)
    cyber_kill_chain = models.JSONField(default=dict)
    stats = models.JSONField(default=dict)
    report_data = models.JSONField(default=dict)      # input of the PDF

    class Meta:
        db_table = "job_summary"


class CveReference(models.Model):

    cve_id = models.CharField(primary_key=True, max_length=32)
    description = models.TextField(blank=True)
    severity_score = models.FloatField(null=True, blank=True)
    affected_platforms = models.CharField(max_length=512, blank=True)
    exploit_availability = models.BooleanField(default=False)

    class Meta:
        db_table = "cve_reference"


class Artifact(models.Model):

    id = models.CharField(
        primary_key=True, max_length=32, default=artifact_id, editable=False
    )
    job = models.ForeignKey(
        CrawlJob, on_delete=models.CASCADE, related_name="artifacts",
        db_column="job_id"
    )
    source = models.CharField(max_length=512)
    raw_text = models.TextField(blank=True)               # redacted
    extracted_entities = models.JSONField(default=dict)   # regex + NER
    collected_at = models.DateTimeField(auto_now_add=True)
    source_type = models.CharField(max_length=32)
    # Extension column (the design's NFR asks for an index by severity):
    # the model's severity for this artifact, copied from the risk score.
    severity = models.CharField(max_length=16, null=True, blank=True)

    cves = models.ManyToManyField(
        CveReference, related_name="artifacts", blank=True,
        db_table="artifact_cve_reference"
    )

    class Meta:
        db_table = "artifact"
        ordering = ["collected_at", "id"]
        indexes = [
            models.Index(fields=["source"]),
            models.Index(fields=["job", "collected_at"]),
            models.Index(fields=["collected_at"]),
            models.Index(fields=["severity"]),
        ]


class KillchainMapping(models.Model):

    id = models.CharField(
        primary_key=True, max_length=32, default=mapping_id, editable=False
    )
    artifact = models.ForeignKey(
        Artifact, on_delete=models.CASCADE, related_name="kill_chain",
        db_column="artifact_id"
    )
    stage = models.CharField(max_length=32)
    confidence = models.FloatField(null=True, blank=True)
    mapping_method = models.CharField(max_length=16)    # rule / ML

    class Meta:
        db_table = "killchain_mapping"
        indexes = [models.Index(fields=["stage"])]


class RiskScore(models.Model):

    id = models.CharField(
        primary_key=True, max_length=32, default=score_id, editable=False
    )
    artifact = models.ForeignKey(
        Artifact, on_delete=models.CASCADE, related_name="risk_scores",
        db_column="artifact_id"
    )
    impact_score = models.FloatField()
    contributing_factors = models.JSONField(default=dict)
    scored_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "risk_score"


class GraphNode(models.Model):

    node_id = models.CharField(
        primary_key=True, max_length=64, default=node_id, editable=False
    )
    artifact = models.ForeignKey(
        Artifact, on_delete=models.CASCADE, related_name="graph_nodes",
        db_column="artifact_id"
    )
    asset_type = models.CharField(max_length=64)       # kill-chain stage
    centrality_score = models.FloatField(default=0.0)

    class Meta:
        db_table = "graph_node"


class GraphEdge(models.Model):

    edge_id = models.CharField(
        primary_key=True, max_length=32, default=edge_id, editable=False
    )
    source_node = models.ForeignKey(
        GraphNode, on_delete=models.CASCADE, related_name="out_edges",
        db_column="source_node_id"
    )
    target_node = models.ForeignKey(
        GraphNode, on_delete=models.CASCADE, related_name="in_edges",
        db_column="target_node_id"
    )
    edge_weight = models.FloatField(default=0.0)

    class Meta:
        db_table = "graph_edge"


class PredictedPath(models.Model):

    path_id = models.CharField(
        primary_key=True, max_length=32, default=path_id, editable=False
    )
    likelihood_score = models.FloatField()
    algorithm_used = models.CharField(max_length=64)

    class Meta:
        db_table = "predicted_path"


class PredictedPathNode(models.Model):

    pk = models.CompositePrimaryKey("path", "node")
    path = models.ForeignKey(
        PredictedPath, on_delete=models.CASCADE, related_name="steps",
        db_column="path_id"
    )
    node = models.ForeignKey(
        GraphNode, on_delete=models.CASCADE, related_name="path_steps",
        db_column="node_id"
    )
    sequence_order = models.IntegerField()

    class Meta:
        db_table = "predicted_path_node"
        ordering = ["sequence_order"]
        constraints = [
            models.UniqueConstraint(
                fields=["path", "sequence_order"], name="uniq_path_order"
            ),
        ]


class EvaluationRecord(models.Model):

    record_id = models.CharField(
        primary_key=True, max_length=32, default=record_id, editable=False
    )
    artifact = models.ForeignKey(
        Artifact, on_delete=models.CASCADE, related_name="evaluations",
        db_column="artifact_id"
    )
    ground_truth_label = models.CharField(max_length=64)
    predicted_label = models.CharField(max_length=64)
    module = models.CharField(max_length=16)           # classifier / path

    class Meta:
        db_table = "evaluation_record"
        indexes = [models.Index(fields=["module"])]


# ============================================================
# EXTENSIONS: the data stores of the DFD (see module docstring)
# ============================================================

class NvdRecord(models.Model):
    """Compact NVD record (id, status, descriptions, CVSS metrics)."""

    cve = models.OneToOneField(
        CveReference, on_delete=models.CASCADE, primary_key=True,
        db_column="cve_id", related_name="nvd"
    )
    in_recent = models.BooleanField(default=False)   # NVD "recent" feed
    record = models.JSONField(default=dict)

    class Meta:
        db_table = "nvd_record"
        indexes = [models.Index(fields=["in_recent"])]


class KevEntry(models.Model):
    """CISA Known Exploited Vulnerabilities catalogue."""

    cve_id = models.CharField(primary_key=True, max_length=32)
    vendor = models.CharField(max_length=256, blank=True)
    product = models.CharField(max_length=256, blank=True)
    name = models.CharField(max_length=512, blank=True)

    class Meta:
        db_table = "kev_entry"


class AttackObject(models.Model):
    """MITRE ATT&CK STIX object (technique, group, software, relationship)."""

    stix_id = models.CharField(primary_key=True, max_length=96)
    object_type = models.CharField(max_length=48, db_index=True)
    record = models.JSONField(default=dict)

    class Meta:
        db_table = "attack_object"


class HistoricalAttack(models.Model):

    attack_name = models.CharField(max_length=256, unique=True)
    record = models.JSONField(default=dict)

    class Meta:
        db_table = "historical_attack"
        ordering = ["id"]


class LabelledSample(models.Model):
    """Labelled evaluation / training set (SRS 15.2, DFD D6)."""

    task = models.CharField(max_length=16)             # severity / stage
    sample_id = models.CharField(max_length=64)
    text = models.TextField()
    label = models.CharField(max_length=64)
    split = models.CharField(max_length=8)             # train / test
    extra = models.JSONField(default=dict)

    class Meta:
        db_table = "labelled_sample"
        ordering = ["task", "sample_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["task", "sample_id"], name="uniq_labelled_sample"
            )
        ]
        indexes = [models.Index(fields=["task", "split"])]


class TrainedModel(models.Model):
    """Serialised classifier (FR-3.3, DFD D4 trained model store)."""

    task = models.CharField(primary_key=True, max_length=32)
    name = models.CharField(max_length=32)
    blob = models.BinaryField()
    trained_at = models.DateTimeField(auto_now=True)
    meta = models.JSONField(default=dict)

    class Meta:
        db_table = "trained_model"


class StoreCache(models.Model):
    """Derived values worth keeping (learned transitions, NER names)."""

    key = models.CharField(primary_key=True, max_length=64)
    value = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "store_cache"


class CrawlSource(models.Model):
    """
    Source registry (FR-1.3). kind "live": an HTTP(S)/onion source with
    an optional "search" block; kind "mock": a local test page whose
    HTML is kept in content (url like mock://forum1.html).
    """

    name = models.CharField(max_length=128, unique=True)
    url = models.CharField(max_length=512)
    category = models.CharField(max_length=64)
    kind = models.CharField(max_length=8, default="live")
    search = models.JSONField(default=dict, blank=True)
    content = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)

    class Meta:
        db_table = "crawl_source"
        ordering = ["id"]


class CorpusDocument(models.Model):
    """Redacted crawl corpus (DFD D1), de-duplicated by content hash."""

    sha1 = models.CharField(primary_key=True, max_length=40)
    url = models.CharField(max_length=512, db_index=True)
    source_type = models.CharField(max_length=16)
    collected_at = models.DateTimeField(auto_now_add=True)
    text = models.TextField()

    class Meta:
        db_table = "corpus_document"


class AuditEvent(models.Model):
    """Every source accessed (FR-1.5)."""

    timestamp = models.DateTimeField()
    job = models.ForeignKey(
        CrawlJob, null=True, blank=True, on_delete=models.SET_NULL,
        db_column="job_id", related_name="audit_events"
    )
    payload = models.JSONField(default=dict)

    class Meta:
        db_table = "audit_event"
        ordering = ["id"]


class AnnotationSample(models.Model):
    """Snippets sampled from the corpus for hand labelling (FR-8.1)."""

    task = models.CharField(max_length=16)             # darkweb / entities
    sample_id = models.CharField(max_length=16)
    source = models.CharField(max_length=500, blank=True)
    source_type = models.CharField(max_length=16, blank=True)
    text = models.TextField()
    labels = models.JSONField(default=dict)            # filled by annotators

    class Meta:
        db_table = "annotation_sample"
        constraints = [
            models.UniqueConstraint(
                fields=["task", "sample_id"], name="uq_annotation_task_sample"
            )
        ]


class StoredReport(models.Model):
    """Named JSON reports (e.g. command-line evaluation output)."""

    name = models.CharField(primary_key=True, max_length=64)
    data = models.JSONField(default=dict)
    generated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "stored_report"


class GeneratedFile(models.Model):
    """Generated PDFs and graph images (DFD D7)."""

    kind = models.CharField(max_length=16)             # pdf / png
    name = models.CharField(max_length=128)
    job = models.ForeignKey(
        CrawlJob, null=True, blank=True, on_delete=models.SET_NULL,
        db_column="job_id", related_name="files"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    content = models.BinaryField()

    class Meta:
        db_table = "generated_file"
        ordering = ["-id"]
