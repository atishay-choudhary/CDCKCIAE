import { useCallback, useEffect, useState } from "react";
import { download, get, post, register, setAuthHandler, signIn, signOut, storeToken, whoAmI } from "./api.js";
const api = { get, post };
import {
  Annotate, AnnotateEntities, Artifacts, AttackGraph, CaseHeader, Evaluation, JobList, KillChain,
  Login, Muted, Paths, Risk, RunPanel, Section, SourceReport, TorBadge,
} from "./components.jsx";

const ACTIVE = ["queued", "running"];

export default function App() {
  const [jobs, setJobs] = useState([]);
  const [jobId, setJobId] = useState(null);
  const [job, setJob] = useState(null);
  const [graph, setGraph] = useState(null);
  const [artifacts, setArtifacts] = useState([]);
  const [artifactId, setArtifactId] = useState(null);
  const [artifact, setArtifact] = useState(null);
  const [mapping, setMapping] = useState(null);
  const [risk, setRisk] = useState(null);
  const [evaluation, setEvaluation] = useState(null);
  const [tor, setTor] = useState(null);
  const [error, setError] = useState("");
  const [filters, setFilters] = useState({ source: "", stage: "", since: "" });
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState("overview");
  const [labelMode, setLabelMode] = useState("classes");
  const [needLogin, setNeedLogin] = useState(false);
  const [who, setWho] = useState(null);

  useEffect(() => {
    setAuthHandler(() => setNeedLogin(true));
    whoAmI().then(setWho).catch(() => {});
  }, []);

  const loadEvaluation = useCallback(
    () => get("/evaluation/metrics").then(setEvaluation).catch(() => setEvaluation({ state: "none" })),
    []
  );

  useEffect(() => {
    if (evaluation?.state !== "running") return;
    const timer = setInterval(loadEvaluation, 3000);
    return () => clearInterval(timer);
  }, [evaluation?.state, loadEvaluation]);

  const runEvaluation = async () => {
    try {
      await post("/evaluation/run", {});
      setEvaluation((e) => ({ ...e, state: "running" }));
    } catch (e) {
      setError(e.message);
    }
  };

  const loadJobs = useCallback(async () => {
    const { jobs: list } = await get("/crawl/jobs");
    setJobs(list);
    return list;
  }, []);

  // job list + Tor indicator
  useEffect(() => {
    loadJobs().catch((e) => setError(e.message));
    loadEvaluation();
    const poll = () => get("/tor/status").then(setTor).catch(() => {});
    poll();
    const timer = setInterval(poll, 15000);
    return () => clearInterval(timer);
  }, [loadJobs, loadEvaluation]);

  // the selected job, refreshed while it is still running
  useEffect(() => {
    if (!jobId) return;
    let stop = false;
    let timer;
    const load = async () => {
      try {
        const detail = await get(`/crawl/status/${jobId}`);
        if (stop) return;
        setJob(detail);
        if (ACTIVE.includes(detail.status)) {
          timer = setTimeout(() => { loadJobs().catch(() => {}); load(); }, 2500);
          return;
        }
        loadJobs().catch(() => {});
        setGraph(await get(`/graph/attack-paths?job=${jobId}`));
        const risky = await get(`/artifacts?job=${jobId}&limit=1`);
        const first = risky.artifacts[0]?.id;
        setRisk(first ? await get(`/risk-score/${first}`) : null);
      } catch (e) {
        if (!stop) setError(e.message);
      }
    };
    setGraph(null);
    setRisk(null);
    setArtifactId(null);
    setArtifact(null);
    setMapping(null);
    load();
    return () => { stop = true; clearTimeout(timer); };
  }, [jobId, loadJobs]);

  // artifact list follows the job and the filters
  useEffect(() => {
    if (!jobId) return;
    const query = new URLSearchParams({ job: jobId });
    for (const [k, v] of Object.entries(filters)) if (v) query.set(k, v);
    get(`/artifacts?${query}`)
      .then((r) => setArtifacts(r.artifacts))
      .catch((e) => setError(e.message));
  }, [jobId, filters, job?.status]);

  useEffect(() => {
    if (!artifactId) return;
    get(`/artifacts/${artifactId}`).then(setArtifact).catch((e) => setError(e.message));
    get(`/killchain/${artifactId}`).then(setMapping).catch(() => setMapping(null));
  }, [artifactId]);

  const start = async ({ mode, keywords, allow_fallback }) => {
    setError("");
    setBusy(true);
    try {
      const { job_id } = await post("/crawl/start", { mode, keywords, allow_fallback });
      await loadJobs();
      setJobId(job_id);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const finished = job && !ACTIVE.includes(job.status);
  const hasResults = finished && job.artifact_count > 0;
  const none = !job
    ? "Nothing open. Start a collection above, or open an earlier one from Cases."
    : finished && !hasResults
      ? "Nothing to show: this collection produced no results (see the notes above)."
      : "Waiting for the collection to finish…";

  const tabs = [
    ["overview", "Situation"],
    ["artifacts", `Artifacts${job?.artifact_count ? ` (${job.artifact_count})` : ""}`],
    ["evaluation", "Evaluation"],
    ["label", "Label"],
  ];

  if (needLogin) {
    return (
      <Login
        onSubmit={async (user, password) => {
          await signIn(user, password);
          window.location.reload();
        }}
        onRegister={async (user, password) => {
          await register(user, password);
          window.location.reload();
        }}
        signupAllowed={who?.signup_allowed}
        onToken={(value) => { storeToken(value); window.location.reload(); }}
      />
    );
  }

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <b>CDKCIAE</b>
          <span>Kill-chain impact assessment</span>
        </div>
        <RunPanel onStart={start} error={error} busy={busy} />
        <TorBadge tor={tor} />
        {who?.authenticated && (
          <div className="account">
            <span>Signed in as <b>{who.username}</b></span>
            {who.is_staff && <a className="adminlink" href="/admin/">Admin</a>}
            <button type="button" className="signout"
              onClick={() => signOut().then(() => window.location.reload())}>
              Sign out
            </button>
          </div>
        )}
      </header>

      <aside className="cases">
        <h2>Cases</h2>
        <JobList jobs={jobs} selected={jobId} onSelect={setJobId} />
      </aside>

      <main className="main">
        <CaseHeader
          job={job}
          actions={hasResults && (
            <button type="button" className="quiet"
              onClick={() => download("/reports/export", { job_id: jobId }, `cdkciae_${jobId}.pdf`)
                .catch((e) => setError(e.message))}>
              Export PDF report
            </button>
          )}
        />

        <nav className="tabs" role="tablist">
          {tabs.map(([id, label]) => (
            <button key={id} type="button" role="tab" aria-selected={tab === id}
              className={tab === id ? "on" : ""} onClick={() => setTab(id)}>{label}</button>
          ))}
        </nav>

        {tab === "overview" && (
          <>
            <Section title="Kill chain" note="The seven stages an intrusion moves through. Tall columns were found in the collected text; height shows confidence.">
              {hasResults ? <KillChain job={job} artifact={artifact} mapping={mapping} /> : <Muted>{none}</Muted>}
            </Section>
            <div className="two">
              <Section title="Risk score" note="CVSS v3.1 environmental, built from the signals found.">
                {hasResults ? <Risk risk={risk} fair={job.business_risk} exposure={job.enterprise_exposure} /> : <Muted>{none}</Muted>}
              </Section>
              <Section title="Predicted attack paths" note="Most likely routes from where the attacker is seen.">
                {hasResults ? <Paths graph={graph} /> : <Muted>{none}</Muted>}
              </Section>
            </div>
            <Section title="Attack graph" note="Red outlines mark the stages most paths pass through.">
              {hasResults ? <AttackGraph graph={graph} /> : <Muted>{none}</Muted>}
            </Section>
            {job?.source_report?.length > 0 && (
              <Section title="What each source returned">
                <SourceReport rows={job.source_report} />
              </Section>
            )}
          </>
        )}

        {tab === "artifacts" && (
          <Section title="Extracted artifacts">
            {job ? (
              <Artifacts list={artifacts} filters={filters} setFilters={setFilters}
                selected={artifactId} onSelect={setArtifactId} detail={artifact}
                onExport={() => download("/reports/export", { artifact_id: artifactId }, `cdkciae_artifact_${artifactId}.pdf`)
                  .catch((e) => setError(e.message))} />
            ) : <Muted>Start a collection to see what it found.</Muted>}
          </Section>
        )}

        {tab === "label" && (
          <Section title="Label dark-web snippets" note="Your own labels are the only test of the models on real dark-web text.">
            <div className="row modes" role="tablist">
              {[["classes", "Severity and stage"], ["entities", "Entities"]].map(([id, text]) => (
                <button key={id} type="button" role="tab" aria-selected={labelMode === id}
                  className={`choice ${labelMode === id ? "on" : ""}`}
                  onClick={() => setLabelMode(id)}>{text}</button>
              ))}
            </div>
            {labelMode === "classes" ? <Annotate api={api} /> : <AnnotateEntities api={api} />}
          </Section>
        )}

        {tab === "evaluation" && (
          <Section title="Model evaluation" note="How the trained models compare with the original rule-based scorer.">
            <Evaluation report={evaluation} onRun={runEvaluation} />
          </Section>
        )}
      </main>
    </div>
  );
}
