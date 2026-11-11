import { useCallback, useEffect, useState } from "react";
import { download, get, post, register, setAuthHandler, signIn, signOut, storeToken, whoAmI } from "./api.js";
const api = { get, post };
import { Login } from "./components.jsx";
import { ArtifactsPage, Collect, EvaluationPage, Home, LabelPage, Results } from "./pages.jsx";
import { useRoute } from "./router.js";
import { SiteFooter, SiteNav } from "./site.jsx";

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
  const [route, go] = useRoute();
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

  // open the newest case once the list arrives, so Results is never empty by default
  useEffect(() => {
    if (!jobId && jobs.length) setJobId(jobs[0].job_id);
  }, [jobs, jobId]);

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

  const onExport = () => download("/reports/export", { job_id: jobId }, `cdkciae_${jobId}.pdf`)
    .catch((e) => setError(e.message));
  const onExportArtifact = () => download("/reports/export", { artifact_id: artifactId }, `cdkciae_artifact_${artifactId}.pdf`)
    .catch((e) => setError(e.message));

  const afterAuth = () => { window.location.hash = "#/collect"; window.location.reload(); };
  const login = (
    <Login
      onSubmit={async (user, password) => { await signIn(user, password); afterAuth(); }}
      onRegister={async (user, password) => { await register(user, password); afterAuth(); }}
      signupAllowed={who?.signup_allowed}
      onToken={(value) => { storeToken(value); afterAuth(); }}
    />
  );

  // the landing page is public; every other page needs a session
  const locked = needLogin && route !== "home";
  if (route === "signin" || locked) return login;

  const page = {
    home: <Home />,
    collect: <Collect tor={tor} job={job} jobs={jobs} jobId={jobId} onStart={start} onOpen={setJobId}
                      error={error} busy={busy} go={go} />,
    results: <Results job={job} jobs={jobs} jobId={jobId} onOpen={setJobId} graph={graph} risk={risk}
                      artifact={artifact} mapping={mapping} onExport={onExport} go={go} />,
    artifacts: <ArtifactsPage job={job} list={artifacts} filters={filters} setFilters={setFilters}
                              selected={artifactId} onSelect={setArtifactId} detail={artifact} onExport={onExportArtifact} />,
    evaluation: <EvaluationPage report={evaluation} onRun={runEvaluation} />,
    label: <LabelPage api={api} />,
  }[route];

  return (
    <div className="site">
      <SiteNav route={route} go={go} who={who} signedOut={needLogin || (who?.login_required && !who.authenticated)}
               onSignOut={() => signOut().then(() => window.location.reload())} />
      <main>
        {error && route !== "collect" && <div className="wrap"><p className="banner bad" role="alert">{error}</p></div>}
        {page}
      </main>
      <SiteFooter />
    </div>
  );
}
