"""
Administration (Django admin at /admin; staff users only).

Users and groups come from django.contrib.auth. The source registry
(FR-1.3) and the annotation samples (FR-8.1) are editable; everything
the pipeline produces (jobs, artifacts, audit trail, reports) is shown
read-only so the evidence cannot be altered from the browser.
"""

from django.contrib import admin

from core.models import (
    AnnotationSample,
    Artifact,
    AuditEvent,
    CrawlJob,
    CrawlSource,
    JobSummary,
    StoredReport,
)


class ReadOnly(admin.ModelAdmin):
    """No adding, editing or deleting through the browser."""

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(CrawlSource)
class CrawlSourceAdmin(admin.ModelAdmin):
    list_display = ("name", "kind", "category", "url", "enabled")
    list_filter = ("kind", "category", "enabled")
    search_fields = ("name", "url")
    list_editable = ("enabled",)
    # the stored HTML of mock pages is not edited here
    exclude = ("content",)

    def get_queryset(self, request):
        return super().get_queryset(request).defer("content")


@admin.register(AnnotationSample)
class AnnotationSampleAdmin(admin.ModelAdmin):
    list_display = ("task", "sample_id", "source_type", "labels")
    list_filter = ("task", "source_type")
    search_fields = ("sample_id", "source")
    readonly_fields = ("task", "sample_id", "source", "source_type", "text")


@admin.register(CrawlJob)
class CrawlJobAdmin(ReadOnly):
    list_display = ("job_id", "source", "status", "started_at", "completed_at")
    list_filter = ("source", "status")
    search_fields = ("job_id",)


@admin.register(JobSummary)
class JobSummaryAdmin(ReadOnly):
    list_display = ("job", "source_used", "outcome", "threat_level", "impact_score", "criticality")
    list_filter = ("outcome", "threat_level", "criticality")
    exclude = ("report_data",)


@admin.register(Artifact)
class ArtifactAdmin(ReadOnly):
    list_display = ("id", "source", "source_type", "severity", "collected_at")
    list_filter = ("source_type", "severity")
    search_fields = ("source", "id")
    exclude = ("raw_text",)


@admin.register(AuditEvent)
class AuditEventAdmin(ReadOnly):
    list_display = ("timestamp", "job", "payload")
    list_filter = ("job",)


@admin.register(StoredReport)
class StoredReportAdmin(ReadOnly):
    list_display = ("name", "generated_at")
    exclude = ("data",)
