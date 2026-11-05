// Presentational pieces. Everything collected from the dark web is
// rendered as React text children, which are escaped: no HTML from
// collected content is ever interpreted.

import { useEffect, useMemo, useState } from "react";

export const STAGES = [
  "Reconnaissance",
  "Weaponization",
  "Delivery",
  "Exploitation",
  "Installation",
  "Command and Control",
  "Actions on Objectives",
];

export const fmt = (value, digits = 2) =>
  typeof value === "number" ? value.toFixed(digits) : "n/a";

export const Section = ({ title, note, children, id }) => (
  <section id={id}>
    <h2>{title}</h2>
    {note && <p className="muted">{note}</p>}
    {children}
  </section>
);

export const Muted = ({ children }) => <p className="muted">{children}</p>;

// ---------------------------------------------------------------- rail

export function TorBadge({ tor }) {
  if (!tor) return null;
  const up = tor.proxy_listening;
  return (
    <div className="tor" title={tor.message}>
      <span className={`dot ${up ? "up" : "down"}`} />
      Tor at {tor.host}:{tor.port} is {up ? "listening" : "not reachable"}
    </div>
  );
}

export function RunPanel({ onStart, error, busy }) {
  const submit = (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    onStart({
      mode: form.get("mode"),
      keywords: form.get("keywords"),
      allow_fallback: form.get("fallback") === "on",
    });
  };
  return (
    <form className="run" onSubmit={submit}>
      <select name="mode" defaultValue="mock" aria-label="Source">
        <option value="mock">Mock corpus</option>
        <option value="live">Live dark web (Tor)</option>
      </select>
      <input type="text" name="keywords" aria-label="Keywords"
             placeholder="Keywords, separated by commas (live)" />
      <label className="check">
        <input type="checkbox" name="fallback" defaultChecked />
        Use the mock corpus if Tor or the sources are unreachable
      </label>
      <button type="submit" disabled={busy}>Start collection</button>
      {error && <span className="error" role="alert">{error}</span>}
    </form>
  );
}

const OUTCOME_LABEL = {
  results: "results",
  no_matches: "no matches",
  fallback: "mock fallback",
  failed: "failed",
};

export function JobList({ jobs, selected, onSelect }) {
  if (!jobs.length) return <p className="muted small">No collections yet.</p>;
  return (
    <ul className="jobs">
      {jobs.map((job) => {
        const state = ACTIVE.includes(job.status)
          ? job.status
          : OUTCOME_LABEL[job.outcome] || job.status;
        return (
          <li key={job.job_id}
              className={`job t-${job.threat_level || ""} ${job.job_id === selected ? "sel" : ""}`}
              onClick={() => onSelect(job.job_id)}>
            <span className="tick" style={{ background: job.threat_level ? "var(--t)" : undefined }} />
            <span>
              <b>{job.threat_level || "No verdict"}</b>
              <small>
                {job.mode}{job.source_mode && job.source_mode !== job.mode ? ` → ${job.source_mode}` : ""}
                {" · "}{job.started_at?.slice(5, 16).replace("T", " ")}
              </small>
            </span>
            <span className="state">{state}</span>
          </li>
        );
      })}
    </ul>
  );
}

const ACTIVE = ["queued", "running"];

// ---------------------------------------------------------------- case

export function CaseHeader({ job, actions }) {
  if (!job) return <Muted>Pick a case on the left, or start a new collection.</Muted>;

  const running = ACTIVE.includes(job.status);
  let banner = null;
  if (running) banner = [`This collection is ${job.status}. Results appear here when it finishes.`, false];
  else if (job.outcome === "no_matches")
    banner = ["Finished, but no page contained your keywords. " + job.message, false];
  else if (job.message) banner = [job.message, job.status === "failed"];

  const ran = job.source_mode && job.source_mode !== job.mode ? ` (ran on ${job.source_mode})` : "";

  return (
    <div className={`verdict t-${job.threat_level || ""}`}>
      <div className="verdict-word">
        <span className="level">{job.threat_level || "No verdict"}</span>
        <span className="where">
          {job.mode}{ran}, started {job.started_at?.replace("T", " ").slice(0, 16)}
          {job.keywords?.length ? `, keywords: ${job.keywords.join(", ")}` : ""}
        </span>
        {actions}
      </div>
      {banner && <div className={`banner ${banner[1] ? "bad" : ""}`}>{banner[0]}</div>}
      <dl className="facts">
        <div><dd>{fmt(job.impact_score, 1)}</dd><dt>Impact, CVSS</dt></div>
        <div><dd>{job.artifact_count ?? 0}</dd><dt>Artifacts</dt></div>
        <div><dd>{job.stats?.signals ?? "n/a"}</dd><dt>Signals</dt></div>
        <div><dd>{job.business_risk?.score ?? "n/a"}<small>/{job.business_risk?.max_score ?? 25}</small></dd><dt>Business risk (FAIR)</dt></div>
        <div><dd>{job.stats?.threat_level_ml || "n/a"}</dd><dt>Model's level, not used for the verdict</dt></div>
      </dl>
    </div>
  );
}

export { SourceReport };

function SourceReport({ rows }) {
  if (!rows?.length) return null;
  return (
    <>
      <div className="scroll">
        <table>
          <thead>
            <tr><th>Source</th><th>Keyword</th><th>Result</th><th>HTTP</th><th>Attempts</th><th>Note</th></tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={i}>
                <td>{row.source}</td>
                <td>{row.keyword || "fixed page"}</td>
                <td>{row.status}</td>
                <td>{row.http_status ?? "–"}</td>
                <td>{row.attempts ?? "–"}</td>
                <td>{row.error || (row.matches || []).join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

// ---------------------------------------------------------- kill chain

export function KillChain({ job, artifact, mapping }) {
  const chain = job?.job_chain || [];
  if (!job || !chain.length) return <Muted>No kill-chain result for this collection.</Muted>;

  const found = Object.fromEntries(chain.map((s) => [s.stage, s]));

  return (
    <div className={`t-${job.threat_level || ""}`}>
      <ol className="strip">
        {STAGES.map((stage, i) => {
          const hit = found[stage];
          const height = hit ? Math.round(30 + 70 * (hit.confidence ?? 0.6)) : 0;
          return (
            <li key={stage} className={hit ? "on" : ""} style={{ "--h": `${height}%`, "--i": i }}>
              <span className="col"><i /></span>
              <b>{stage}</b>
              <small>
                {hit ? `${hit.method}${hit.confidence != null ? `, ${fmt(hit.confidence)}` : ""}` : "not seen"}
              </small>
            </li>
          );
        })}
      </ol>
      {mapping?.artifact_stages?.length > 0 && (
        <p className="muted small">
          Selected artifact: {mapping.artifact_stages
            .map((m) => `${m.stage} (${m.mapping_method}, ${fmt(m.confidence)})`).join(", ")}
        </p>
      )}
      {job.ml_only?.length > 0 && (
        <p className="muted small">
          Stages only the model suggested{job.ml_adds_stages ? "" : " (kept out of the chain until validated)"}:{" "}
          {job.ml_only.map((s) => s.stage || s).join(", ")}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- risk

function FairTable({ title, model, score, level }) {
  if (!model?.factors) return null;
  return (
    <>
      <h3>{title}: {model[score]}/{model.max_score}, {model[level]}</h3>
      <p className="muted small">{model.model}. Each factor is a level from 1 to 5 taken from the evidence shown.</p>
      <div className="scroll">
        <table>
          <thead><tr><th>Factor</th><th>Level</th><th>Basis</th></tr></thead>
          <tbody>
            {Object.entries(model.factors).map(([name, f]) => (
              <tr key={name}>
                <td>{name.replaceAll("_", " ")}</td>
                <td>{f.level}/5</td>
                <td className="small">{f.basis}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

export function Risk({ risk, fair, exposure }) {
  if (!risk || risk.impact_score == null)
    return <Muted>No risk score for this job.</Muted>;
  const factors = risk.contributing_factors?.factors || {};
  const scenarios = risk.contributing_factors?.scenarios || [];
  return (
    <>
      <div className={`gauge-row t-${risk.criticality || ""}`}>
        <svg className="gauge" viewBox="0 0 200 112" role="img"
             aria-label={`Impact score ${fmt(risk.impact_score, 1)} out of 10`}>
          <path d="M14 100 A86 86 0 0 1 186 100" pathLength="100" className="gauge-track" />
          <path d="M14 100 A86 86 0 0 1 186 100" pathLength="100" className="gauge-fill"
                strokeDasharray={`${Math.min(risk.impact_score, 10) * 10} 100`} />
          <text x="100" y="92" textAnchor="middle" className="gauge-num">{fmt(risk.impact_score, 1)}</text>
        </svg>
        <dl className="facts stack">
          <div><dd>{risk.criticality || "n/a"}</dd><dt>Criticality</dt></div>
          <div><dd>{factors.severity ?? "n/a"}</dd><dt>CVSS base severity</dt></div>
          <div><dd>{factors.asset_importance ?? "n/a"}</dd><dt>Asset importance</dt></div>
        </dl>
      </div>
      <p className="muted small">{risk.scope_note}</p>
      <h3>Exposure and attack probability</h3>
      <pre>
        {JSON.stringify(
          { exposure: factors.exposure, attack_probability: factors.attack_probability },
          null,
          2
        )}
      </pre>
      <FairTable title="Business risk" model={fair} score="score" level="risk_level" />
      <FairTable title="Enterprise exposure" model={exposure} score="exposure_score" level="exposure_level" />
      {scenarios.length > 0 && (
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Scenario</th>
                <th>Vector</th>
                <th>Base</th>
                <th>Req.</th>
                <th>Env.</th>
              </tr>
            </thead>
            <tbody>
              {scenarios.map((s, i) => (
                <tr key={i}>
                  <td>{s.scenario}</td>
                  <td className="small">{s.vector}</td>
                  <td>{fmt(s.base_score, 1)}</td>
                  <td>{s.security_requirement}</td>
                  <td>{fmt(s.environmental_score, 1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

// --------------------------------------------------------------- paths

export function Paths({ graph }) {
  if (!graph?.paths?.length)
    return <Muted>{graph?.message || "No predicted paths for this job."}</Muted>;
  const top = Math.max(...graph.paths.map((p) => p.likelihood)) || 1;
  return (
    <>
      {graph.paths.map((p) => (
        <div key={p.path_id}>
          <div className="path">
            {p.path.map((stage, i) => (
              <span key={i}>
                {i > 0 && " → "}
                <span className="chip">{stage}</span>
              </span>
            ))}
            <span className="muted small">
              {" "}
              likelihood {fmt(p.likelihood, 4)}
            </span>
          </div>
          <div className="meter">
            <i style={{ width: `${(p.likelihood / top) * 100}%` }} />
          </div>
        </div>
      ))}
      <p className="muted small">
        Algorithm: {graph.paths[0].algorithm}. Bars are scaled to the most
        likely path.
      </p>
      <h3>Stages most paths pass through</h3>
      <div className="row">
        {graph.centrality.slice(0, 6).map((c) => (
          <span key={c.stage} className="chip">
            {c.stage} {fmt(c.centrality, 3)}
          </span>
        ))}
      </div>
    </>
  );
}

// --------------------------------------------------------------- graph

export function AttackGraph({ graph }) {
  const layout = useMemo(() => {
    if (!graph?.nodes?.length) return null;
    const names = graph.nodes.map((n) => n.asset_type);
    // layer = longest path from any entry (graph is acyclic by construction)
    const layer = Object.fromEntries(names.map((n) => [n, 0]));
    for (let pass = 0; pass < names.length; pass++)
      for (const e of graph.edges)
        layer[e.target] = Math.max(layer[e.target], layer[e.source] + 1);
    const columns = {};
    names.forEach((n) => (columns[layer[n]] ||= []).push(n));
    const colW = 190, rowH = 52, margin = 80;
    const pos = {};
    let tallest = 1;
    for (const [c, list] of Object.entries(columns)) {
      tallest = Math.max(tallest, list.length);
      list.forEach((n, i) => (pos[n] = [margin + c * colW, 40 + i * rowH]));
    }
    const top = Math.max(...graph.edges.map((e) => e.weight), 1e-9);
    const critical = Math.max(...graph.nodes.map((n) => n.centrality_score), 1e-9);
    return {
      pos,
      width: 2 * margin + (Object.keys(columns).length - 1) * colW,
      height: 60 + tallest * rowH,
      top,
      critical,
    };
  }, [graph]);

  if (!layout) return <Muted>No graph for this job.</Muted>;

  return (
    <svg className="graph" viewBox={`0 0 ${layout.width} ${layout.height}`} role="img"
         aria-label="Attack graph with predicted edges and critical stages">
      {graph.edges.map((e, i) => {
        const [x1, y1] = layout.pos[e.source];
        const [x2, y2] = layout.pos[e.target];
        return (
          <line key={i} x1={x1 + 66} y1={y1} x2={x2 - 66} y2={y2}
                stroke="var(--link)"
                strokeWidth={0.8 + 3 * (e.weight / layout.top)} opacity=".55" />
        );
      })}
      {graph.nodes.map((n) => {
        const [x, y] = layout.pos[n.asset_type];
        const hot = n.centrality_score >= layout.critical * 0.8;
        return (
          <g key={n.node_id}>
            <rect x={x - 66} y={y - 16} width={132} height={32} rx={8}
                  fill="var(--paper)"
                  stroke={hot ? "var(--critical)" : "var(--link)"}
                  strokeWidth={hot ? 2.5 : 1} />
            <text x={x} y={y + 4} textAnchor="middle">{n.asset_type}</text>
          </g>
        );
      })}
    </svg>
  );
}

// ----------------------------------------------------------- artifacts

export function Artifacts({ list, filters, setFilters, selected, onSelect, detail, onExport }) {
  return (
    <>
      <div className="row filters">
        <input type="text" placeholder="filter by source" value={filters.source}
               onChange={(e) => setFilters({ ...filters, source: e.target.value })} />
        <select value={filters.severity || ""}
                onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
                aria-label="Model severity">
          <option value="">any severity</option>
          {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={filters.stage}
                onChange={(e) => setFilters({ ...filters, stage: e.target.value })}
                aria-label="Kill-chain stage">
          <option value="">any stage</option>
          {STAGES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <input type="date" value={filters.since} aria-label="Collected since"
               onChange={(e) => setFilters({ ...filters, since: e.target.value })} />
      </div>
      {!list.length ? (
        <Muted>No artifacts for this selection.</Muted>
      ) : (
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Source</th><th>Type</th><th>Entities</th><th>Regex / NER</th>
                <th>Stage (model)</th><th>Collected</th>
              </tr>
            </thead>
            <tbody>
              {list.map((a) => (
                <tr key={a.id} className={`pick ${a.id === selected ? "sel" : ""}`}
                    onClick={() => onSelect(a.id)}>
                  <td>{a.source}</td>
                  <td>{a.source_type}</td>
                  <td className="small">
                    {Object.entries(a.entity_counts).map(([k, v]) => `${k}: ${v}`).join(", ") || "none"}
                  </td>
                  <td>{a.extraction?.regex ?? "—"} / {a.extraction?.ner ?? "—"}</td>
                  <td>{a.ml_stage || "—"}</td>
                  <td>{a.collected_at?.replace("T", " ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {detail && <ArtifactDetail a={detail} onExport={onExport} />}
    </>
  );
}

function ArtifactDetail({ a, onExport }) {
  return (
    <>
      <button type="button" className="quiet" onClick={onExport}>Export PDF for this artifact</button>
      <h3>Entities (regex + NER, merged)</h3>
      <pre>{JSON.stringify(a.entities, null, 2)}</pre>
      {a.extraction && (
        <p className="muted small">
          Regex found {a.extraction.regex ?? "n/a"}, NER found{" "}
          {a.extraction.ner ?? "n/a"}, duplicates removed on merge:{" "}
          {a.extraction.duplicates_removed ?? "n/a"}.
        </p>
      )}
      {a.cves?.length > 0 && (
        <>
          <h3>CVE references</h3>
          <ul>
            {a.cves.map((c) => (
              <li key={c.cve_id}>
                {c.cve_id} · CVSS {fmt(c.severity_score, 1)}
                {c.exploit_availability ? " · known exploited" : ""}
                {c.affected_platforms ? ` · ${c.affected_platforms}` : ""}
              </li>
            ))}
          </ul>
        </>
      )}
      <h3>Text ({a.text_note})</h3>
      <pre>{a.text}</pre>
    </>
  );
}

// ---------------------------------------------------------- evaluation

const Matrix = ({ m }) => {
  if (!m?.rows_true_cols_predicted) return null;
  return (
    <div className="scroll">
      <table className="cm">
        <thead>
          <tr><th>True \ predicted</th>{m.labels.map((l) => <th key={l}>{l}</th>)}</tr>
        </thead>
        <tbody>
          {m.labels.map((t, i) => {
            const row = m.rows_true_cols_predicted[i];
            const total = row.reduce((a, b) => a + b, 0) || 1;
            return (
              <tr key={t}>
                <th>{t}</th>
                {row.map((v, j) => (
                  <td key={j} style={{
                    background: `color-mix(in srgb, ${i === j ? "var(--low)" : "var(--critical)"} ${Math.round((v / total) * 70)}%, transparent)`,
                  }}>{v}</td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

const Score = ({ value }) => (
  <>
    <span className="score" style={{ width: `${Math.round((value || 0) * 120)}px` }} />
    {fmt(value, 3)}
  </>
);

export function Evaluation({ report, onRun }) {
  if (!report) return <Muted>Loading…</Muted>;
  const running = report.state === "running";

  const head = (
    <div className="provenance">
      <button type="button" className={report.state === "none" ? "" : "quiet"} disabled={running} onClick={onRun}>
        {running ? "Evaluating…" : report.state === "none" ? "Run evaluation" : "Retrain and re-evaluate"}
      </button>
      <span className="muted small">
        {running
          ? "Training both classifiers and scoring them against the rule-based baseline. This takes a minute or two."
          : report.state === "ready"
            ? `Stored in the database ${report.generated_at?.replace("T", " ")} · ${report.message} · model ${report.model}`
            : "Nothing has been evaluated yet. The numbers below come only from a run you start here."}
      </span>
    </div>
  );

  if (report.state === "none") return head;

  const parts = [];

  for (const [task, t] of Object.entries(report.classifier || {})) {
    const cv = t.classifier_cv_macro_f1;
    parts.push(
      <div key={task}>
        <h3>{task === "severity" ? "Severity" : "Kill-chain stage"} classifier on {t.test_rows} held-out rows</h3>
        <div className="scroll">
          <table>
            <thead><tr><th>System</th><th>Accuracy</th><th>Macro-F1</th></tr></thead>
            <tbody>
              {[["Rule-based baseline", t.baseline], ["Tuned baseline", t.baseline_tuned], ["Trained classifier", t.classifier]].map(([n, m]) => (
                <tr key={n}><td>{n}</td><td><Score value={m?.accuracy} /></td><td><Score value={m?.macro_f1} /></td></tr>
              ))}
            </tbody>
          </table>
        </div>
        {cv && <p className="muted">5-fold cross-validated macro-F1: {fmt(cv.mean, 3)} ± {fmt(cv.std, 3)}</p>}
        <Matrix m={t.classifier?.confusion_matrix} />
      </div>
    );
  }

  const p = report.paths;
  if (p) {
    const rows = [["Held-out ATT&CK groups", p.held_out_groups], ["Historical incidents", p.incidents]];
    parts.push(
      <div key="paths">
        <h3>Attack-path prediction against the baseline</h3>
        <div className="scroll">
          <table>
            <thead><tr>{["Test set", "System", "Precision", "Recall", "F1", "Path support", "Edge support"].map((c) => <th key={c}>{c}</th>)}</tr></thead>
            <tbody>
              {rows.flatMap(([n, r]) => [["baseline", r.baseline], ["model", r.model]].map(([sys, m]) => (
                <tr key={n + sys}>
                  <td>{n} ({r.cases})</td><td>{sys}</td>
                  <td>{fmt(m.precision, 3)}</td><td>{fmt(m.recall, 3)}</td><td>{fmt(m.f1, 3)}</td>
                  <td>{fmt(m.path_support, 2)}</td><td>{fmt(m.edge_support, 2)}</td>
                </tr>
              )))}
            </tbody>
          </table>
        </div>
        <p className="muted">
          Calibration error (lower is better): baseline {fmt(p.calibration?.baseline, 3)}, model {fmt(p.calibration?.model, 3)}.
        </p>
        {p.edge_prediction && (
          <>
            <h3>Which transitions real attackers use</h3>
            <p className="muted">
              {p.edge_prediction.edges} stage-to-stage transitions, 5-fold cross-validated. The set-overlap
              scores above favour the baseline because it always returns the deepest path; this one tests
              the learned probabilities directly.
            </p>
            <table>
              <thead><tr><th>System</th><th>AUC (higher is better)</th><th>Brier (lower is better)</th></tr></thead>
              <tbody>
                {[["Baseline (uniform)", p.edge_prediction.baseline], ["Learned from ATT&CK", p.edge_prediction.model]].map(([n, m]) => (
                  <tr key={n}><td>{n}</td><td>{fmt(m.auc, 3)}</td><td>{fmt(m.brier, 3)}</td></tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    );
  }

  if (report.ner)
    parts.push(<div key="ner"><h3>NER against regex</h3><pre>{JSON.stringify(report.ner.merged || report.ner, null, 2)}</pre></div>);

  return <>{head}{parts}</>;
}

// ---------------------------------------------------------- annotation

export function Annotate({ api }) {
  const [data, setData] = useState(null);
  const [index, setIndex] = useState(0);
  const [scores, setScores] = useState(null);
  const [scoring, setScoring] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    api.get("/annotation/samples").then(setData).catch((e) => setError(e.message));
  }, [api]);

  if (error) return <p className="error" role="alert">{error}</p>;
  if (!data) return <Muted>Loading…</Muted>;
  if (!data.samples.length)
    return (
      <Muted>
        No snippets sampled yet. Run <code>python -m engine.evaluation.darkweb_validation export</code> once
        after you have collected some live pages.
      </Muted>
    );

  const sample = data.samples[index];
  const done = data.samples.filter((s) => s.severity).length;

  const set = async (field, value) => {
    setError("");
    try {
      await api.post("/annotation/label", { id: sample.id, [field]: value });
      setData((d) => ({
        ...d,
        samples: d.samples.map((s) => (s.id === sample.id ? { ...s, [field]: value } : s)),
      }));
    } catch (e) {
      setError(e.message);
    }
  };

  const nextOpen = () => {
    const order = [...data.samples.keys()];
    const after = order.slice(index + 1).concat(order.slice(0, index));
    const open = after.find((i) => !data.samples[i].severity);
    setIndex(open ?? Math.min(index + 1, data.samples.length - 1));
  };

  const runScore = () => {
    setScoring(true);
    api.get("/annotation/score")
      .then((r) => setScores(r.reports))
      .catch((e) => setError(e.message))
      .finally(() => setScoring(false));
  };

  return (
    <div className="annotate">
      <div className="annotate-main">
        <p className="muted">
          Snippet {index + 1} of {data.samples.length}. {done} have a severity label. Read it, then set what
          you would assign by hand, without looking at what the system says.
        </p>
        <blockquote className="snippet">{sample.text}</blockquote>

        <h3>Severity</h3>
        <div className="choices">
          {data.severity_labels.map((l) => (
            <button key={l} type="button"
              className={`choice t-${l} ${sample.severity === l ? "on" : ""}`}
              onClick={() => set("severity", l)}>{l}</button>
          ))}
        </div>

        <h3>Kill-chain stage</h3>
        <div className="choices">
          {data.stage_labels.map((l) => (
            <button key={l} type="button"
              className={`choice ${sample.stage === l ? "on" : ""}`}
              onClick={() => set("stage", l)}>{l}</button>
          ))}
          <button type="button" className={`choice ${sample.stage === "" ? "on" : ""}`}
            onClick={() => set("stage", "")}>No stage applies</button>
        </div>

        <div className="row nav">
          <button type="button" className="quiet" disabled={index === 0}
            onClick={() => setIndex(index - 1)}>Previous</button>
          <button type="button" onClick={nextOpen}>Next unlabelled</button>
        </div>
      </div>

      <div className="annotate-side">
        <h3>Progress</h3>
        <div className="dots" role="list">
          {data.samples.map((s, i) => (
            <button key={s.id} type="button" role="listitem" aria-label={`Snippet ${i + 1}`}
              className={`dot-btn ${s.severity ? "set" : ""} ${i === index ? "cur" : ""}`}
              onClick={() => setIndex(i)} />
          ))}
        </div>

        <h3>Score the models</h3>
        <p className="muted small">
          Compares the trained classifier and both rule-based baselines with your labels. Below about
          30 labelled snippets the numbers are not reliable.
        </p>
        <button type="button" className="quiet" disabled={done === 0 || scoring} onClick={runScore}>
          {scoring ? "Scoring…" : "Score now"}
        </button>

        {scores && Object.keys(scores).length === 0 && <Muted>Nothing labelled yet.</Muted>}
        {scores && Object.entries(scores).map(([task, t]) => (
          <div key={task}>
            <h3>{task === "severity" ? "Severity" : "Stage"}, {t.test_rows} labelled</h3>
            <table>
              <thead><tr><th>System</th><th>Accuracy</th><th>Macro-F1</th></tr></thead>
              <tbody>
                {[["Rule-based", t.baseline], ["Tuned baseline", t.baseline_tuned], ["Trained", t.classifier]].map(([n, m]) => (
                  <tr key={n}><td>{n}</td><td>{fmt(m?.accuracy, 3)}</td><td>{fmt(m?.macro_f1, 3)}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- sign in

export function Login({ onSubmit, onRegister, signupAllowed, onToken }) {
  const [creating, setCreating] = useState(false);
  const [user, setUser] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    try {
      await (creating ? onRegister : onSubmit)(user, password);
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <form className="login" onSubmit={submit}>
      <h1>CDKCIAE</h1>
      <p className="muted small">
        {creating ? "Create an account to run and keep your own collections." : "Sign in to view your collections and reports."}
      </p>
      <label>User name
        <input type="text" value={user} autoComplete="username"
               onChange={(e) => setUser(e.target.value)} required />
      </label>
      <label>Password
        <input type="password" value={password} autoComplete={creating ? "new-password" : "current-password"}
               onChange={(e) => setPassword(e.target.value)} required />
      </label>
      {creating && <p className="muted small">User name: 3-30 letters, digits, . _ - . Password: at least 8 characters, not a common one.</p>}
      {error && <div className="banner bad">{error}</div>}
      <button type="submit">{creating ? "Create account" : "Sign in"}</button>
      {signupAllowed && (
        <button type="button" className="quiet"
          onClick={() => { setCreating(!creating); setError(""); }}>
          {creating ? "I already have an account" : "Create an account"}
        </button>
      )}
      <button type="button" className="quiet"
        onClick={() => { const t = window.prompt("API token (CDKCIAE_API_TOKEN):"); if (t) onToken(t); }}>
        Use an API token instead
      </button>
    </form>
  );
}
