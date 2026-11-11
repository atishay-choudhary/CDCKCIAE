// Who built the project and what it was measured against. Edit this file
// to change the Home page; entries left null are not shown.

export const CREDITS = {
  members: [{ name: "Atishay Choudhary", role: "Design and development" },{ name: "Janvi Kushwaha", role: "Design and development" }],
  supervisor: null, // { name: "...", title: "..." }
  institution: null, // "College name"
  programme: null, // "Degree, semester, course"
  year: null, // "Academic year"
};

// Measured by the project's own evaluation (Evaluation page re-runs it).
export const EVIDENCE = [
  { title: "CVSS scores against NVD", note: "Environmental calculator, exact match",
    bars: [{ label: "1,394 of 1,394 identical", value: 100 }] },
  { title: "Kill-chain stage classifier", note: "Macro F1 on held-out text",
    bars: [{ label: "Linear SVM 0.88", value: 88 }, { label: "XGBoost 0.77", value: 77, dim: true }] },
  { title: "Next-stage prediction", note: "AUC over 1,642 transitions, 5-fold",
    bars: [{ label: "Graph neural network 0.80", value: 80 },
           { label: "Learned from ATT&CK 0.72", value: 72, dim: true },
           { label: "Equal-odds guess 0.36", value: 36, dim: true }] },
  { title: "Severity classifier", note: "Macro F1 on vulnerability text",
    bars: [{ label: "0.66. Not yet validated on dark-web text; your labels decide whether it can drive the verdict.", value: 66, flag: true }] },
];

export const STANDARDS = [
  ["MITRE ATT&CK", "The techniques and intrusion sets the stage models and the path predictor learn from."],
  ["NVD and CVSS v3.1", "The vulnerability records and the scoring maths behind every impact figure."],
  ["CISA KEV", "The catalogue of vulnerabilities known to be exploited, which raises a finding's weight."],
  ["Open FAIR", "The factors behind the business-risk score: how often, how likely, how costly."],
  ["spaCy", "Named-entity recognition for organisations, places and products, tuned with ATT&CK terms."],
  ["Tor and Ahmia", "The route live collection takes to reach onion search results."],
];
