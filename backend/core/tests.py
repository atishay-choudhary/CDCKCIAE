"""
Run from the project root:  python backend/manage.py test core

Jobs run synchronously here (run_job); no Tor or network is needed.
"""

import builtins
import json
import os
import re
from pathlib import Path
from unittest import mock

from django.test import TestCase, override_settings

from core import services
from core.models import (
    Artifact,
    CrawlJob,
    EvaluationRecord,
    GraphEdge,
    GraphNode,
    JobSummary,
    PredictedPath,
    PredictedPathNode,
)


ROOT = Path(__file__).resolve().parents[2]


class DataTestCase(TestCase):
    """A test database that already holds the mock pages (crawl_source)."""

    @classmethod
    def setUpTestData(cls):

        from core import ingest

        ingest.seed_sources({
            p.name: p.read_text(encoding="utf-8")
            for p in sorted((ROOT / "mock_sites").glob("*.html"))
        })


def make_job(mode, keywords=(), allow_fallback=True):

    job = CrawlJob.objects.create(source=mode)

    JobSummary.objects.create(
        job=job, keywords=list(keywords), allow_fallback=allow_fallback
    )

    return job


def post(client, path, body):

    return client.post(
        path, data=json.dumps(body), content_type="application/json"
    )


class ValidationTests(TestCase):

    def test_content_type_must_be_json(self):

        res = self.client.post(
            "/crawl/start", data="mode=mock", content_type="text/plain"
        )

        self.assertEqual(res.status_code, 415)

    def test_bad_requests(self):

        for body in (
            {"mode": "other"},
            {"mode": "live"},
            {"mode": "live", "keywords": ["x"] * 21},
            {"mode": "live", "keywords": ["y" * 65]},
        ):
            self.assertEqual(post(self.client, "/crawl/start", body).status_code, 400)

    @override_settings(API_TOKEN="s3cret")
    def test_token_required_when_configured(self):

        self.assertEqual(self.client.get("/crawl/jobs").status_code, 401)

        res = self.client.get(
            "/crawl/jobs", HTTP_AUTHORIZATION="Bearer s3cret"
        )

        self.assertEqual(res.status_code, 200)

    def test_dashboard_page(self):

        res = self.client.get("/")

        self.assertContains(res, "CDKCIAE Dashboard")

        self.assertIn("script-src 'self'", res["Content-Security-Policy"])

        script = re.search(r'src="(/assets/[^"]+\.js)"', res.content.decode())

        self.assertEqual(self.client.get(script.group(1)).status_code, 200)


class MockJobTests(DataTestCase):

    @classmethod
    def setUpTestData(cls):

        super().setUpTestData()

        cls.job = make_job("mock")

        services.run_job(cls.job.job_id)

    def test_job_completed_and_persisted(self):

        job = CrawlJob.objects.get(pk=self.job.job_id)

        self.assertEqual(job.status, "completed", job.summary.message)

        self.assertEqual(job.summary.source_used, "mock")

        self.assertEqual(job.artifacts.count(), 3)

        self.assertTrue(job.summary.cyber_kill_chain["stages"])

    def test_documented_tables_and_relations(self):

        job = CrawlJob.objects.get(pk=self.job.job_id)

        # one risk score per artifact; string primary keys
        for artifact in job.artifacts.all():

            self.assertEqual(artifact.risk_scores.count(), 1)

            self.assertTrue(artifact.id.startswith("art_"))

        nodes = GraphNode.objects.filter(artifact__job=job)

        self.assertTrue(nodes.exists())

        # every edge joins two nodes of this job
        for edge in GraphEdge.objects.filter(source_node__in=nodes):

            self.assertIn(edge.target_node, nodes)

        # a predicted path is an ordered sequence of graph nodes
        path = PredictedPath.objects.first()

        orders = list(
            PredictedPathNode.objects.filter(path=path)
            .values_list("sequence_order", flat=True)
        )

        self.assertEqual(orders, list(range(len(orders))))

        self.assertGreaterEqual(len(orders), 1)

    def test_endpoints(self):

        status = self.client.get(f"/crawl/status/{self.job.job_id}").json()

        self.assertEqual(status["status"], "completed")

        listing = self.client.get(f"/artifacts?job={self.job.job_id}").json()

        self.assertEqual(listing["total"], 3)

        artifact_id = listing["artifacts"][0]["id"]

        detail = self.client.get(f"/artifacts/{artifact_id}").json()

        self.assertIn("text", detail)

        self.assertIn("cves", detail)

        chain = self.client.get(f"/killchain/{artifact_id}").json()

        self.assertTrue(chain["job_chain"])

        risk = self.client.get(f"/risk-score/{artifact_id}").json()

        self.assertEqual(risk["scope"], "job")

        self.assertIsNotNone(risk["impact_score"])

        graph = self.client.get(
            f"/graph/attack-paths?job={self.job.job_id}"
        ).json()

        self.assertTrue(graph["paths"])

        self.assertTrue(graph["nodes"])

        self.assertTrue(graph["edges"])

        self.assertEqual(self.client.get("/artifacts/nope").status_code, 404)

    def test_pdf_export(self):

        res = post(self.client, "/reports/export", {"job_id": self.job.job_id})

        self.assertEqual(res.status_code, 200, res.content[:200])

        self.assertTrue(res.content.startswith(b"%PDF"))

    def test_evaluation_is_empty_until_run(self):

        report = self.client.get("/evaluation/metrics").json()

        self.assertEqual(report["state"], "none")

        self.assertIsNone(report["classifier"])

    def test_evaluation_records_give_metrics(self):

        artifact = Artifact.objects.first()

        for truth, predicted in (("HIGH", "HIGH"), ("HIGH", "LOW"), ("LOW", "LOW")):

            services.record_evaluation(
                artifact, truth, predicted, "classifier:severity"
            )

        records = services.evaluation_from_records()["classifier:severity"]

        self.assertEqual(records["records"], 3)

        self.assertAlmostEqual(records["accuracy"], 0.6667, places=3)

        self.assertEqual(EvaluationRecord.objects.count(), 3)

    def test_run_uses_the_database_not_data_files(self):

        from core.models import CorpusDocument

        real_open = builtins.open
        touched = []

        def spy(file, *args, **kwargs):

            name = str(file)

            if name.lower().endswith((".json", ".jsonl", ".csv", ".joblib")):
                touched.append(name)

            return real_open(file, *args, **kwargs)

        job = make_job("mock")

        with mock.patch("builtins.open", spy):
            services.run_job(job.job_id)

        self.assertEqual(touched, [])

        self.assertTrue(CorpusDocument.objects.exists())

    def test_stored_text_is_redacted(self):

        for artifact in self.job.artifacts.all():

            self.assertNotIn("@credit-reporting.com", artifact.raw_text)


class LiveFallbackTests(DataTestCase):

    TOR_DOWN = {"status": False, "message": "Tor SOCKS proxy not reachable"}

    def test_live_falls_back_to_mock_when_tor_is_down(self):

        job = make_job("live", ["leak"])

        with mock.patch(
            "engine.crawlers.tor_session.test_tor_connection",
            return_value=self.TOR_DOWN
        ):
            services.run_job(job.job_id)

        job.refresh_from_db()

        self.assertEqual(job.status, "completed", job.summary.message)

        self.assertEqual(job.source, "live")

        self.assertEqual(job.summary.source_used, "mock")

        from core.models import AuditEvent

        self.assertTrue(
            AuditEvent.objects.filter(
                job=job, payload__mode="mock-fallback"
            ).exists()
        )

        self.assertEqual(job.summary.outcome, "fallback")

        self.assertIn("NOT live data", job.summary.message)

    def test_fallback_can_be_disabled(self):

        job = make_job("live", ["leak"], allow_fallback=False)

        with mock.patch(
            "engine.crawlers.tor_session.test_tor_connection",
            return_value=self.TOR_DOWN
        ):
            services.run_job(job.job_id)

        job.refresh_from_db()

        self.assertEqual(job.status, "failed")

        self.assertIn("fallback disabled", job.summary.message)

    def test_no_keyword_match_is_explained_not_empty(self):

        job = make_job("live", ["zzz"])

        with mock.patch(
            "engine.crawlers.tor_session.test_tor_connection",
            return_value={"status": True, "message": "ok"}
        ), mock.patch(
            "engine.pipeline_DW.run_darkweb_pipeline",
            return_value={"status": "no_matches"}
        ):
            services.run_job(job.job_id)

        job.refresh_from_db()

        self.assertEqual(job.status, "completed")

        self.assertEqual(job.summary.source_used, "live")

        self.assertEqual(job.summary.outcome, "no_matches")

        self.assertEqual(job.artifacts.count(), 0)

        # the page's endpoints must answer, not 404, for this job
        for url in (
            f"/graph/attack-paths?job={job.job_id}",
            "/graph/attack-paths",
            f"/crawl/status/{job.job_id}",
        ):
            self.assertEqual(self.client.get(url).status_code, 200, url)

        graph = self.client.get(f"/graph/attack-paths?job={job.job_id}").json()

        self.assertEqual(graph["outcome"], "no_matches")

        self.assertEqual(graph["nodes"], [])


class TorTests(TestCase):

    def test_status_reports_configured_endpoint(self):

        with mock.patch(
            "engine.crawlers.tor_session.proxy_listening", return_value=False
        ):
            body = self.client.get("/tor/status").json()

        self.assertEqual(body["port"], 9050)

        self.assertFalse(body["proxy_listening"])

        self.assertIn("CDKCIAE_TOR_PORT", body["message"])

    def test_host_and_port_come_from_environment(self):

        import importlib

        import engine.crawlers.tor_session as tor

        with mock.patch.dict(
            "os.environ", {"CDKCIAE_TOR_HOST": "tor", "CDKCIAE_TOR_PORT": "9150"}
        ):
            importlib.reload(tor)

            self.assertEqual((tor.TOR_HOST, tor.TOR_PORT), ("tor", 9150))

        importlib.reload(tor)


class PersistWithModelOutputTests(DataTestCase):
    """The trained-model fields and CVE links (not present without models)."""

    def test_ml_stage_and_cve_rows(self):

        from engine.pipeline import run_pipeline

        output = run_pipeline()

        records = output["artifact_records"]

        records[0]["entities"] = {"cves": ["CVE-2099-0001"]}

        output["threat_assessment"]["documents"] = [
            {"severity": "HIGH", "severity_confidence": 0.8,
             "kill_chain_stage": "Initial Access", "kill_chain_confidence": 0.7}
        ] * len(records)

        job = make_job("mock")

        with mock.patch("core.services._collect",
                        return_value=(output, "mock", "results", "")):
            services.run_job(job.job_id)

        job.refresh_from_db()

        self.assertEqual(job.status, "completed", job.summary.message)

        first = job.artifacts.get(source=records[0]["source"])

        self.assertEqual(first.kill_chain.get().mapping_method, "ML")

        self.assertEqual(first.cves.get().cve_id, "CVE-2099-0001")

        listing = self.client.get(f"/artifacts?job={job.job_id}&stage=Initial Access").json()

        self.assertEqual(listing["total"], len(records))

        self.assertEqual(listing["artifacts"][0]["ml_severity"], "HIGH")
