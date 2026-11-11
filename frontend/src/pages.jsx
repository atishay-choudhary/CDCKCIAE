// The seven pages. Data and handlers come from App; the pieces that draw
// collected content live in components.jsx.
import { useState } from "react";
import { CREDITS, EVIDENCE, STANDARDS } from "./credits.js";
import {
  Annotate, AnnotateEntities, Artifacts, AttackGraph, CaseHeader, Evaluation, JobList, KillChain,
  Muted, Paths, Risk, Section, SourceReport, TorBadge, title,
} from "./components.jsx";

const ACTIVE = ["queued", "running"];

// ---------------------------------------------------------------- home

// Stages lit in the hero trace: found, guessed by the classifier, or not seen.
const TRACE = [
  ["Reconnaissance", "off", 60, 160, "mid"], ["Weaponization", "guess", 240, 120, "mid"],
  ["Delivery", "on", 420, 160, "mid"], ["Exploitation", "on", 600, 120, "mid"],
  ["Installation", "guess", 780, 160, "mid"], ["Command and Control", "off", 960, 120, "mid"],
  ["Actions on Objectives", "on", 1140, 160, "end"],
];
const TRACE_PATH = "M60 160 H150 L190 120 H300 L340 160 H480 L520 120 H660 L700 160 H840 L880 120 H1020 L1060 160 H1140";

function Trace() {
  return (
    <figure className="trace">
      <svg viewBox="0 0 1200 250" width="100%" role="img"
           aria-label="The seven kill-chain stages joined by one trace. Delivery, Exploitation and Actions on Objectives are lit as found; Weaponization and Installation carry a dashed ring as classifier guesses.">
        <path className="base" d={TRACE_PATH} />
        <path className="run" d={TRACE_PATH} />
        {TRACE.map(([name, state, x, y, anchor], i) => (
          <g key={name} className={`node ${state}`} style={{ "--n": i }}>
            {state === "guess" && <circle className="ring" cx={x} cy={y} r="13" />}
            <circle className="dot" cx={x} cy={y} r={state === "on" ? 10 : 7} />
            <text x={x} y={y < 150 ? y - 36 : y + 38} textAnchor={anchor === "end" ? "end" : "middle"}>{name}</text>
          </g>
        ))}
      </svg>
      <figcaption className="muted small">
        Blue marks a stage found in the collected text. A dashed magenta ring is the classifier's guess,
        shown but not counted in the verdict.
      </figcaption>
    </figure>
  );
}

const STEPS = [
  ["Collect", "Search the dark web through Tor for the terms you give it, or load the built-in sample corpus when Tor is not available."],
  ["Read", "Pull out CVEs, email addresses, IPs, domains and named entities. Pattern matching and spaCy work side by side so you can compare them."],
  ["Place", "Map the findings onto the seven kill-chain stages and predict the most likely route an attacker takes from there."],
  ["Score", "Rate the impact with CVSS v3.1, the business risk with Open FAIR, and how much of your own estate is exposed."],
];

function Credits() {
  const { members, supervisor, institution, programme, year } = CREDITS;
  const right = [
    supervisor && [`Guided by ${supervisor.name}`, supervisor.title],
    institution && [institution, [programme, year].filter(Boolean).join(". ")],
  ].filter(Boolean);
  return (
    <div className="glass hot credits">
      <h2>Built by</h2>
      <div className="grid2">
        <div className="stack">
          {members.map((m) => (
            <div key={m.name}><h3>{m.name}</h3>{m.role && <p className="muted small">{m.role}</p>}</div>
          ))}
        </div>
        {right.length > 0 && (
          <div className="stack">
            {right.map(([head, sub]) => (
              <div key={head}><h3>{head}</h3>{sub && <p className="muted small">{sub}</p>}</div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export function Home() {
  return (
    <>
      <section className="hero dots">
        <div className="wrap">
          <h1>See where an attack stands in the kill chain, and what it would cost.</h1>
          <p className="lede">CDKCIAE reads dark-web and public threat text, places what it finds on the seven stages
            of the cyber kill chain, and scores the business impact with CVSS and FAIR.</p>
          <div className="cta">
            <a className="btn" href="#/collect">Start a collection</a>
            <a className="btn ghost" href="#/results">Open results</a>
          </div>
          <Trace />
        </div>
      </section>

      <section className="band">
        <div className="wrap grid2 top">
          <div>
            <h2>From raw pages to a decision you can defend</h2>
            <p className="muted">Every number in a result can be traced back to the text, the model or the standard that produced it.</p>
          </div>
          <ol className="steps">
            {STEPS.map(([title, text], i) => (
              <li key={title} className={i === STEPS.length - 1 ? "last" : ""}><h3>{title}</h3><p className="muted">{text}</p></li>
            ))}
          </ol>
        </div>
      </section>

      <section className="band">
        <div className="wrap">
          <h2>Checked against real data, not assumed</h2>
          <p className="muted">Each model is scored on text it was not trained on. Where a result is still weak, the page says so.</p>
          <div className="glass evidence">
            {EVIDENCE.map((row) => (
              <div className="ev" key={row.title}>
                <div><h3>{row.title}</h3><p className="muted small">{row.note}</p></div>
                <div className="stack tight">
                  {row.bars.map((b) => (
                    <div key={b.label}>
                      <div className="meter"><i className={b.flag ? "mag" : b.dim ? "dim" : ""} style={{ width: `${b.value}%` }} /></div>
                      <p className={`small ${b.dim ? "muted" : ""}`}>{b.label}</p>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="band">
        <div className="wrap">
          <h2>Built on public standards</h2>
          <div className="grid3">
            {STANDARDS.map(([name, text]) => <div key={name}><h3>{name}</h3><p className="muted small">{text}</p></div>)}
          </div>
        </div>
      </section>

      <section className="band last"><div className="wrap"><Credits /></div></section>
    </>
  );
}

// ------------------------------------------------------------- collect

export function Collect({ tor, job, jobs, jobId, onStart, onOpen, error, busy, go }) {
  const [mode, setMode] = useState("live");
  const submit = (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    onStart({ mode, keywords: form.get("keywords"), allow_fallback: form.get("fallback") === "on" });
  };
  const running = job && ACTIVE.includes(job.status);
  return (
    <div className="wrap page">
      <h1 className="h2">Start a collection</h1>
      <p className="lede">Name what you are watching for. CDKCIAE searches for it, reads what comes back and builds the assessment.</p>

      <form className="glass ice runbar" onSubmit={submit}>
        <div className="runrow">
          <div className="field">
            <span className="label" id="mode-label">Source</span>
            <div className="seg" role="group" aria-labelledby="mode-label">
              {[["mock", "Sample corpus"], ["live", "Live dark web"]].map(([id, text]) => (
                <button key={id} type="button" aria-pressed={mode === id} onClick={() => setMode(id)}>{text}</button>
              ))}
            </div>
          </div>
          <label className="field grow">Search terms
            <input type="text" name="keywords" placeholder="Terms separated by commas" disabled={mode === "mock"} />
          </label>
          <button type="submit" className="btn" disabled={busy || running}>Start collection</button>
        </div>
        <div className="runrow between">
          <label className="check">
            <input type="checkbox" name="fallback" defaultChecked />
            <span>Fall back to the sample corpus if Tor or the sources cannot be reached, so the run still finishes.</span>
          </label>
          <TorBadge tor={tor} />
        </div>
        {error && <p className="error" role="alert">{error}</p>}
      </form>

      <div className="grid2 top split">
        <section aria-labelledby="now-h">
          <h2 id="now-h">Running now</h2>
          {job ? (
            <>
              <p className="muted small">
                {running
                  ? "A live run usually takes two to three minutes, because every search goes through Tor. This page updates itself."
                  : "The latest collection has finished."}
              </p>
              <div className="meter busy"><i className={running ? "indeterminate" : ""} style={running ? undefined : { width: "100%" }} /></div>
              <p>
                <b>{running ? job.status : job.threat_level ? `${title(job.threat_level)} threat` : job.outcome || job.status}</b>
                {job.keywords?.length ? `, searching ${job.keywords.join(", ")}` : ""}
              </p>
              {job.message && <p className="muted small">{job.message}</p>}
              <p><a href="#/results" onClick={() => onOpen(job.job_id)}>{running ? "Watch it on the Results page" : "See the results"}</a></p>
            </>
          ) : <Muted>Nothing is running. Start a collection above.</Muted>}
        </section>
        <section aria-labelledby="recent-h">
          <h2 id="recent-h">Recent cases</h2>
          <p className="muted small">Only your own collections appear here.</p>
          <JobList jobs={jobs} selected={jobId} onSelect={(id) => { onOpen(id); go("results"); }} />
        </section>
      </div>
    </div>
  );
}

// ------------------------------------------------------------- results

export function Results({ job, jobs, jobId, onOpen, graph, risk, artifact, mapping, onExport, go }) {
  const finished = job && !ACTIVE.includes(job.status);
  const has = finished && job.artifact_count > 0;
  const none = !job
    ? "Nothing open. Start a collection, or open an earlier case below."
    : finished ? "Nothing to show: this collection produced no results (see the notes above)."
      : "Waiting for the collection to finish…";
  return (
    <div className="wrap page">
      <CaseHeader job={job}
        actions={has && <button type="button" className="quiet" onClick={onExport}>Export PDF report</button>} />
      <details className="cases" open={!job}>
        <summary>Cases ({jobs.length})</summary>
        <JobList jobs={jobs} selected={jobId} onSelect={onOpen} />
        <p className="small"><a href="#/collect">Start a new collection</a></p>
      </details>

      <Section title="Kill chain"
        note="The seven stages an intrusion moves through. Solid columns were found in the collected text; height shows confidence.">
        {has ? <KillChain job={job} artifact={artifact} mapping={mapping} /> : <Muted>{none}</Muted>}
      </Section>
      <div className="grid2 top">
        <Section title="Risk score" note="CVSS v3.1 environmental, built from the signals found.">
          {has ? <Risk risk={risk} fair={job.business_risk} exposure={job.enterprise_exposure} /> : <Muted>{none}</Muted>}
        </Section>
        <Section title="Predicted attack paths" note="Most likely routes from where the attacker is seen.">
          {has ? <Paths graph={graph} /> : <Muted>{none}</Muted>}
        </Section>
      </div>
      <Section title="Attack graph" note="Magenta outlines mark the stages most paths pass through.">
        {has ? <AttackGraph graph={graph} /> : <Muted>{none}</Muted>}
      </Section>
      {job?.source_report?.length > 0 && (
        <Section title="What each source returned"><SourceReport rows={job.source_report} />
          <p><a href="#/artifacts">Read the extracted artifacts</a></p>
        </Section>
      )}
    </div>
  );
}

// ------------------------------------------------- artifacts, evaluation, label

export function ArtifactsPage({ job, list, filters, setFilters, selected, onSelect, detail, onExport }) {
  return (
    <div className="wrap page">
      <h1 className="h2">Artifacts</h1>
      <p className="lede">Every page the collection kept, with what was pulled out of it. Pick a row to read it.</p>
      {job ? (
        <Artifacts list={list} filters={filters} setFilters={setFilters} selected={selected}
          onSelect={onSelect} detail={detail} onExport={onExport} />
      ) : <Muted>Start a collection to see what it found.</Muted>}
    </div>
  );
}

export function EvaluationPage({ report, onRun }) {
  return (
    <div className="wrap page">
      <h1 className="h2">Evaluation</h1>
      <p className="lede">How each model scores on text it never saw while learning, compared with the original rule-based scorer.</p>
      <Evaluation report={report} onRun={onRun} />
    </div>
  );
}

export function LabelPage({ api }) {
  const [mode, setMode] = useState("classes");
  return (
    <div className="wrap page">
      <h1 className="h2">Label snippets</h1>
      <p className="lede">Your own labels are the only fair test of the models on real dark-web text.</p>
      <div className="seg modes" role="group" aria-label="What to label">
        {[["classes", "Severity and stage"], ["entities", "Entities"]].map(([id, text]) => (
          <button key={id} type="button" aria-pressed={mode === id} onClick={() => setMode(id)}>{text}</button>
        ))}
      </div>
      {mode === "classes" ? <Annotate api={api} /> : <AnnotateEntities api={api} />}
    </div>
  );
}

