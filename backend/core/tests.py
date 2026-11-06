"""
Run from the project root:  python backend/manage.py test core

Jobs run synchronously here (run_job); no Tor or network is needed.
"""

import builtins
import io
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


class AnnotationTests(TestCase):

    def setUp(self):

        from engine import datastore

        datastore.annotation_replace("darkweb", [
            {"id": "dw-001", "text": "selling remote code execution exploit",
             "source": "https://example.invalid/x", "source_type": "live"},
        ])

    def test_samples_hide_the_source_url(self):

        body = self.client.get("/annotation/samples").json()

        self.assertEqual(len(body["samples"]), 1)

        self.assertNotIn("source", body["samples"][0])

    def test_label_and_validation(self):

        ok = post(self.client, "/annotation/label",
                  {"id": "dw-001", "severity": "HIGH", "stage": "Delivery"})

        self.assertEqual(ok.status_code, 200)

        sample = self.client.get("/annotation/samples").json()["samples"][0]

        self.assertEqual((sample["severity"], sample["stage"]), ("HIGH", "Delivery"))

        bad = post(self.client, "/annotation/label",
                   {"id": "dw-001", "severity": "SEVERE"})

        self.assertEqual(bad.status_code, 400)

        missing = post(self.client, "/annotation/label",
                       {"id": "dw-999", "severity": "LOW"})

        self.assertEqual(missing.status_code, 404)

    def test_score_without_labels_is_empty(self):

        self.assertEqual(self.client.get("/annotation/score").json(), {"reports": {}})


class FairRiskTests(TestCase):
    """FR-6.2: business risk and exposure are traceable FAIR factors."""

    def test_factors_and_range(self):
        from engine.intelligence.fair_risk import assess_business_risk

        signals = [{"subtype": "sale"}, {"subtype": "exploit"}] * 4
        consequences = [{"severity": "HIGH", "compliance_effects": ["GDPR exposure"]}]
        cvss = {"scenarios": [{"environmental_score": 7.2}]}
        out = assess_business_risk(signals, consequences, cvss, [{"kev": True}])

        self.assertEqual(out["factors"]["threat_event_frequency"]["level"], 4)
        self.assertEqual(out["factors"]["vulnerability"]["level"], 5)
        self.assertEqual(out["factors"]["loss_magnitude"]["level"], 4)
        self.assertEqual(out["score"], 20)
        self.assertEqual(out["risk_level"], "CRITICAL")
        self.assertTrue(1 <= out["score"] <= out["max_score"])

    def test_empty_input_is_lowest(self):
        from engine.intelligence.fair_risk import assess_business_risk, assess_exposure

        out = assess_business_risk([], [], {}, [])
        self.assertEqual((out["score"], out["risk_level"]), (1, "LOW"))
        self.assertEqual(assess_exposure([])["exposure_level"], "LOW")

    def test_exposure_uses_asset_value_and_breadth(self):
        from engine.intelligence.fair_risk import assess_exposure

        assets = [
            {"criticality": "CRITICAL", "asset_type": "ip", "asset_role": "gateway"},
            {"criticality": "LOW", "asset_type": "email", "asset_role": "user"},
        ]
        out = assess_exposure(assets)
        self.assertEqual(out["factors"]["asset_value"]["level"], 5)
        self.assertEqual(out["exposure_score"], 10)
        self.assertEqual(out["exposure_level"], "HIGH")


class SeverityColumnTests(DataTestCase):
    """NFR: artifacts are indexed and filterable by severity."""

    def test_severity_saved_and_filterable(self):

        from core.models import Artifact
        from engine.pipeline import run_pipeline

        output = run_pipeline()
        records = output["artifact_records"]
        output["threat_assessment"]["documents"] = [
            {"severity": "HIGH", "severity_confidence": 0.8}
        ] * len(records)

        job = make_job("mock")

        with mock.patch("core.services._collect",
                        return_value=(output, "mock", "results", "")):
            services.run_job(job.job_id)

        self.assertEqual(set(job.artifacts.values_list("severity", flat=True)), {"HIGH"})
        self.assertIn(["severity"], [i.fields for i in Artifact._meta.indexes])

        hit = self.client.get(f"/artifacts?job={job.job_id}&severity=HIGH").json()
        miss = self.client.get(f"/artifacts?job={job.job_id}&severity=LOW").json()
        self.assertEqual((hit["total"], miss["total"]), (len(records), 0))


class ArtifactPdfTests(DataTestCase):
    """UC-8: a report for one selected artifact."""

    def test_artifact_pdf_and_errors(self):

        job = make_job("mock")
        services.run_job(job.job_id)
        artifact = job.artifacts.first()

        reply = self.client.post(
            "/reports/export", json.dumps({"artifact_id": artifact.id}),
            content_type="application/json",
        )
        self.assertEqual(reply.status_code, 200)
        self.assertTrue(reply.content.startswith(b"%PDF"))
        self.assertIn(artifact.id, reply["Content-Disposition"])

        missing = self.client.post(
            "/reports/export", json.dumps({"artifact_id": "nope"}),
            content_type="application/json",
        )
        self.assertEqual(missing.status_code, 404)


@override_settings(REQUIRE_LOGIN=True)
class LoginTests(TestCase):
    """Use case "Authenticate": user sessions next to the bearer token."""

    H = {"HTTP_X_REQUESTED_WITH": "cdkciae"}

    def setUp(self):
        from django.contrib.auth import get_user_model
        from django.core.cache import cache

        cache.clear()
        get_user_model().objects.create_user("analyst", password="s3cret-pass")

    def login(self, password="s3cret-pass"):
        return self.client.post(
            "/auth/login", json.dumps({"username": "analyst", "password": password}),
            content_type="application/json", **self.H,
        )

    def test_blocked_until_signed_in(self):
        self.assertEqual(self.client.get("/crawl/jobs").status_code, 401)
        self.assertTrue(self.client.get("/auth/me").json()["login_required"])

        self.assertEqual(self.login().status_code, 200)
        self.assertEqual(self.client.get("/crawl/jobs").status_code, 200)
        self.assertEqual(self.client.get("/auth/me").json()["username"], "analyst")

    def test_wrong_password_and_throttle(self):
        for _ in range(5):
            self.assertEqual(self.login("bad").status_code, 401)

        self.assertEqual(self.login("bad").status_code, 429)
        self.assertEqual(self.login().status_code, 429)

    def test_session_post_needs_custom_header(self):
        self.login()
        body = json.dumps({"mode": "mock", "keywords": []})

        forged = self.client.post("/crawl/start", body, content_type="application/json")
        self.assertEqual(forged.status_code, 403)

        text = self.client.post("/crawl/start", body, content_type="text/plain", **self.H)
        self.assertEqual(text.status_code, 415)

    def test_logout(self):
        self.login()
        out = self.client.post("/auth/logout", "{}", content_type="application/json", **self.H)
        self.assertEqual(out.status_code, 200)
        self.assertEqual(self.client.get("/crawl/jobs").status_code, 401)

    def test_login_needs_header_and_json(self):
        plain = self.client.post("/auth/login", "{}", content_type="application/json")
        self.assertEqual(plain.status_code, 403)

    @override_settings(API_TOKEN="tok")
    def test_bearer_token_still_works(self):
        ok = self.client.get("/crawl/jobs", HTTP_AUTHORIZATION="Bearer tok")
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(self.client.get("/crawl/jobs").status_code, 401)


class ImportSourcesTests(TestCase):
    """FR-1.3: a documented source list can be loaded and validated."""

    def run_import(self, entries, *flags):
        import tempfile
        from django.core.management import call_command

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(entries, f)

        try:
            call_command("import_sources", f.name, *flags, stdout=io.StringIO())
        finally:
            os.unlink(f.name)

    def test_import_update_and_disable(self):
        from core.models import CrawlSource

        self.run_import([
            {"name": "A", "url": "http://a.example/", "category": "forum"},
            {"name": "B", "url": "https://b.example/", "category": "search_engine",
             "search": {"url": "https://b.example/s", "param": "q"}},
        ])
        self.assertEqual(CrawlSource.objects.filter(kind="live").count(), 2)

        self.run_import([{"name": "A", "url": "http://a.example/", "category": "paste"}],
                        "--disable-missing")
        self.assertEqual(CrawlSource.objects.get(name="A").category, "paste")
        self.assertFalse(CrawlSource.objects.get(name="B").enabled)

    def test_bad_entry_writes_nothing(self):
        from django.core.management.base import CommandError
        from core.models import CrawlSource

        with self.assertRaises(CommandError):
            self.run_import([
                {"name": "ok", "url": "http://x.example/", "category": "forum"},
                {"name": "bad", "url": "ftp://x.example/", "category": "forum"},
            ])
        self.assertFalse(CrawlSource.objects.filter(name="ok").exists())


class AdminTests(DataTestCase):
    """The admin site: staff only; pipeline output is read-only."""

    def test_anonymous_redirected_and_staff_can_manage_sources(self):
        from django.contrib.auth import get_user_model

        self.assertEqual(self.client.get("/admin/").status_code, 302)

        get_user_model().objects.create_superuser("boss", password="s3cret-pass")
        self.client.login(username="boss", password="s3cret-pass")

        self.assertEqual(self.client.get("/admin/").status_code, 200)
        self.assertEqual(self.client.get("/admin/core/crawlsource/").status_code, 200)
        self.assertEqual(self.client.get("/admin/auth/user/").status_code, 200)

        job = make_job("mock")
        services.run_job(job.job_id)
        self.assertEqual(self.client.get("/admin/core/artifact/").status_code, 200)
        self.assertEqual(self.client.get("/admin/core/artifact/add/").status_code, 403)
        first = job.artifacts.first().pk
        self.assertEqual(
            self.client.post(f"/admin/core/artifact/{first}/delete/", {"post": "yes"}).status_code, 403
        )

    def test_non_staff_user_is_refused(self):
        from django.contrib.auth import get_user_model

        get_user_model().objects.create_user("viewer", password="s3cret-pass")
        self.client.login(username="viewer", password="s3cret-pass")
        self.assertEqual(self.client.get("/admin/").status_code, 302)


class OwnershipTests(DataTestCase):
    """Each user sees only the collections they started."""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        from django.contrib.auth import get_user_model

        User = get_user_model()
        cls.ann = User.objects.create_user("ann", password="s3cret-pass")
        cls.bob = User.objects.create_user("bob", password="s3cret-pass")
        cls.boss = User.objects.create_superuser("boss", password="s3cret-pass")

        cls.job = make_job("mock")
        cls.job.owner = cls.ann
        cls.job.save()
        services.run_job(cls.job.job_id)
        cls.artifact = cls.job.artifacts.first()

    def as_user(self, name):
        self.client.logout()
        self.assertTrue(self.client.login(username=name, password="s3cret-pass"))

    def test_owner_sees_job(self):
        self.as_user("ann")
        ids = [j["job_id"] for j in self.client.get("/crawl/jobs").json()["jobs"]]
        self.assertIn(self.job.job_id, ids)
        self.assertEqual(self.client.get(f"/crawl/status/{self.job.job_id}").status_code, 200)

    def test_other_user_sees_nothing_of_it(self):
        self.as_user("bob")
        self.assertEqual(self.client.get("/crawl/jobs").json()["jobs"], [])
        self.assertEqual(self.client.get(f"/crawl/status/{self.job.job_id}").status_code, 404)
        self.assertEqual(self.client.get(f"/artifacts?job={self.job.job_id}").json()["total"], 0)
        self.assertEqual(self.client.get(f"/artifacts/{self.artifact.id}").status_code, 404)
        self.assertEqual(self.client.get(f"/killchain/{self.artifact.id}").status_code, 404)
        self.assertEqual(self.client.get(f"/risk-score/{self.artifact.id}").status_code, 404)
        self.assertEqual(
            self.client.get(f"/graph/attack-paths?job={self.job.job_id}").status_code, 404
        )
        self.assertEqual(self.client.get("/graph/attack-paths").json()["nodes"], [])

        for body in ({"job_id": self.job.job_id}, {"artifact_id": self.artifact.id}):
            reply = self.client.post(
                "/reports/export", json.dumps(body), content_type="application/json",
                HTTP_X_REQUESTED_WITH="cdkciae",
            )
            self.assertEqual(reply.status_code, 404)

    def test_new_job_belongs_to_the_starter(self):
        self.as_user("bob")
        with mock.patch("core.services.threading.Thread"):
            reply = self.client.post(
                "/crawl/start", json.dumps({"mode": "mock"}),
                content_type="application/json", HTTP_X_REQUESTED_WITH="cdkciae",
            )
        self.assertEqual(reply.status_code, 202)
        self.assertEqual(CrawlJob.objects.get(pk=reply.json()["job_id"]).owner, self.bob)
        self.assertEqual(len(self.client.get("/crawl/jobs").json()["jobs"]), 1)

    def test_superuser_sees_everything(self):
        self.as_user("boss")
        ids = [j["job_id"] for j in self.client.get("/crawl/jobs").json()["jobs"]]
        self.assertIn(self.job.job_id, ids)

    def test_assign_jobs_command(self):
        from django.core.management import call_command

        old = make_job("mock")
        call_command("assign_jobs", "bob", stdout=io.StringIO())
        old.refresh_from_db()
        self.assertEqual(old.owner, self.bob)
        self.assertEqual(CrawlJob.objects.get(pk=self.job.job_id).owner, self.ann)


class SignupTests(TestCase):

    H = {"HTTP_X_REQUESTED_WITH": "cdkciae"}

    def setUp(self):
        from django.core.cache import cache

        cache.clear()

    def sign_up(self, name="newuser", password="a-long-pass-2026"):
        return self.client.post(
            "/auth/register", json.dumps({"username": name, "password": password}),
            content_type="application/json", **self.H,
        )

    def test_create_account_signs_in_and_is_not_staff(self):
        from django.contrib.auth import get_user_model

        reply = self.sign_up()
        self.assertEqual(reply.status_code, 201)
        user = get_user_model().objects.get(username="newuser")
        self.assertFalse(user.is_staff or user.is_superuser)
        self.assertEqual(self.client.get("/auth/me").json()["username"], "newuser")

    def test_rejects_duplicates_and_weak_input(self):
        self.assertEqual(self.sign_up().status_code, 201)
        self.client.logout()
        self.assertEqual(self.sign_up("NEWUSER").status_code, 409)
        self.assertEqual(self.sign_up("ab").status_code, 400)
        self.assertEqual(self.sign_up("other", "12345678").status_code, 400)
        self.assertEqual(self.sign_up("third", "short").status_code, 400)

    @override_settings(ALLOW_SIGNUP=False)
    def test_can_be_turned_off(self):
        self.assertEqual(self.sign_up().status_code, 403)
        self.assertFalse(self.client.get("/auth/me").json()["signup_allowed"])

    def test_needs_header(self):
        reply = self.client.post(
            "/auth/register", json.dumps({"username": "x1y", "password": "a-long-pass-2026"}),
            content_type="application/json",
        )
        self.assertEqual(reply.status_code, 403)


class EntityLabellingTests(DataTestCase):
    """Entity labels: reviewed-empty snippets count, scoring works from the API."""

    H = {"HTTP_X_REQUESTED_WITH": "cdkciae"}

    def setUp(self):
        from engine import datastore

        datastore.annotation_replace("entities", [
            {"id": "ent-001", "text": "Contact admin@evil.example about CVE-2024-1234 at 10.1.2.3",
             "source": "https://example.invalid/a", "source_type": "live"},
            {"id": "ent-002", "text": "nothing useful in this one",
             "source": "https://example.invalid/b", "source_type": "live"},
        ])

    def label(self, sample_id, labels):
        return self.client.post(
            "/annotation/entities/label", json.dumps({"id": sample_id, "labels": labels}),
            content_type="application/json",
        )

    def test_samples_hide_source_and_start_unreviewed(self):
        body = self.client.get("/annotation/entities").json()
        self.assertEqual(len(body["samples"]), 2)
        self.assertNotIn("source", body["samples"][0])
        self.assertFalse(any(s["reviewed"] for s in body["samples"]))
        self.assertIn("emails", body["types"])

    def test_empty_labels_count_as_reviewed_and_are_scored(self):
        self.assertEqual(self.client.get("/annotation/entities/score").status_code, 409)

        self.assertEqual(self.label("ent-001", {
            "emails": "admin@evil.example", "cves": "CVE-2024-1234", "ipv4": "10.1.2.3",
        }).status_code, 200)
        self.assertEqual(self.label("ent-002", {}).status_code, 200)

        samples = self.client.get("/annotation/entities").json()["samples"]
        self.assertTrue(all(s["reviewed"] for s in samples))

        reply = self.client.get("/annotation/entities/score")
        self.assertEqual(reply.status_code, 200)
        report = reply.json()["report"]
        self.assertEqual(report["rows"], 2)
        self.assertEqual(report["support"]["ALL"], 3)
        self.assertGreater(report["regex"]["ALL"]["recall"], 0.9)

    def test_validation(self):
        self.assertEqual(self.label("ent-001", {"colours": "red"}).status_code, 400)
        self.assertEqual(self.label("ent-999", {"emails": "a@b.c"}).status_code, 404)
        bad = self.client.post("/annotation/entities/label", "{}", content_type="text/plain")
        self.assertEqual(bad.status_code, 415)


class EntityCompareTests(DataTestCase):
    """UC-2: the two extractors' results are kept apart and shown side by side."""

    def test_merge_returns_both_inputs(self):
        from engine.nlp.entity_merge import merge_entities

        out = merge_entities({"cves": ["CVE-1"]}, {"organizations": ["Acme"], "cves": ["cve-1"]})
        self.assertEqual(out["regex_entities"], {"cves": ["CVE-1"]})
        self.assertEqual(out["ner_entities"], {"cves": ["cve-1"], "organizations": ["Acme"]})
        self.assertEqual(out["entities"], {"cves": ["CVE-1"], "organizations": ["Acme"]})
        self.assertEqual(out["duplicates_removed"], 1)

    def test_artifact_detail_has_both_lists_and_summary_stays_small(self):
        from engine.pipeline import run_pipeline

        output = run_pipeline()
        records = output["artifact_records"]
        records[0]["regex_entities"] = {"cves": ["CVE-2099-0001"]}
        records[0]["ner_entities"] = {"organizations": ["Acme Corp"]}

        job = make_job("mock")
        with mock.patch("core.services._collect", return_value=(output, "mock", "results", "")):
            services.run_job(job.job_id)

        first = job.artifacts.get(source=records[0]["source"])
        detail = self.client.get(f"/artifacts/{first.id}").json()
        self.assertEqual(detail["regex_entities"], {"cves": ["CVE-2099-0001"]})
        self.assertEqual(detail["ner_entities"], {"organizations": ["Acme Corp"]})
        self.assertNotIn("regex_entities", detail["extraction"])

        listing = self.client.get(f"/artifacts?job={job.job_id}").json()["artifacts"][0]
        self.assertNotIn("regex_entities", listing["extraction"])
