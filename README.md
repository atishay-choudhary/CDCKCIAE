# CDKCIAE: Cross-Domain Kill-Chain Impact Assessment Engine

A Python threat-intelligence engine that maps vulnerability and threat data onto the Cyber Kill Chain, scores severity, predicts likely attack paths, and generates analyst-style reports. It combines public vulnerability data (NVD, CISA KEV, MITRE ATT&CK) with text collected from dark-web-style sources.

B.Tech major project, Jagran Lakecity University (CSE). Built on an earlier minor project (May 2026).

---

## What it does

1. **Collects** threat text from forum, marketplace, and leak-style sources (offline mock sites included, optional live collection over Tor).
2. **Extracts** indicators and entities (CVE IDs, IPs, hashes, and similar) with regex and NLP.
3. **Classifies** each item by **kill-chain stage** and **severity** using TF-IDF models.
4. **Maps** findings to the seven Cyber Kill Chain stages and to MITRE ATT&CK techniques.
5. **Builds a threat graph** with learned stage-transition weights, finds the most likely attack paths, and ranks critical stages by betweenness centrality.
6. **Scores impact** with CVSS v3.1 environmental metrics (real NVD vectors for CVEs, auditable assumed vectors for signal classes) instead of hand-assigned weights.
7. **Reports** results as a visual threat graph and a PDF intelligence report.

## Architecture

```
datasets (NVD, CISA KEV, MITRE ATT&CK, historical attacks)
        |
crawlers  ->  extractors  ->  nlp  ->  ml (stage / severity)
                                          |
                          intelligence (kill-chain mapper, threat scorer,
                          asset mapper, propagation + consequence + impact engines)
                                          |
                                graph (threat graph, path prediction)
                                          |
                                reports (PDF) + evaluation
```

| Package | Responsibility |
|---|---|
| `engine/crawlers` | Forum / dark-web collection, Tor session handling, source lists |
| `engine/extractors`, `engine/nlp` | Indicator extraction, preprocessing, TF-IDF and keyword analysis, entities |
| `engine/ml` | Trainable stage and severity classifiers, inference |
| `engine/intelligence` | Kill-chain mapping, threat scoring, impact and propagation modelling, narratives |
| `engine/graph` | Threat graph construction, path prediction, visualization |
| `engine/reports` | PDF report generation |
| `engine/evaluation` | Dataset builder, metrics, CVSS and dark-web validation, path evaluation |

## Data

- **NVD CVE feeds** (2024, 2025, recent, modified) and **CISA Known Exploited Vulnerabilities**
- **MITRE ATT&CK** (enterprise)
- **Labelled sets** built by `engine/evaluation/dataset_builder.py`: about 88,800 rows for severity and 560 for kill-chain stage, with a fixed train/test split
- **Historical attack records** used to evaluate path prediction

Large raw datasets are not tracked in Git. Download the NVD, CISA KEV, and MITRE ATT&CK files into the `datasets/` folders shown in the project tree.

## Implementation status against the SRS

The major-project SRS defines seven objectives (O1 to O7). Current status:

| Objective |
|---|
| O1 Trained ML classifier replacing keyword scoring | 
| O2 spaCy / NER extraction alongside regex |
| O3 Weighted path prediction and centrality |
| O4 CVSS-grounded impact scoring |
| O5 Stabilised live Tor crawler |
| O6 Evaluation framework and baseline comparison |
| O7 Web dashboard, REST API, database |

## Setup

Requires Python 3.12 or newer.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install scikit-learn joblib networkx matplotlib reportlab requests beautifulsoup4 pyfiglet colorama
```

## Usage

```bash
# Main CLI (offline pipeline over local datasets and mock sites)
python main.py

# Train the classifiers
python -m engine.ml.classifier --task severity --model logreg
python -m engine.ml.classifier --task stage --model logreg

# Evaluate against baselines
python -m engine.evaluation.evaluate --model logreg
python -m engine.evaluation.path_evaluation
```

Outputs (graph, PDF report, evaluation JSON) are written to `outputs/`.

### Live dark-web mode (optional)

`main_DW.py` runs the live demo and needs a local Tor client listening on `127.0.0.1:9050`. Use it only for authorized research, and only against sources you are permitted to access. For everyday development, use the bundled `mock_sites/`.

## Results

Evaluated on the fixed held-out split.

| Task | Model | Accuracy | Macro-F1 | Keyword-heuristic baseline |
|---|---|---|---|---|
| Kill-chain stage | Logistic regression (TF-IDF) | 84.8% | 0.90 | 5.4% accuracy |
| Severity (LOW / MEDIUM / HIGH / CRITICAL) | Logistic regression (TF-IDF) | 69.5% | 0.63 | 13.5% accuracy |

The severity test set has 17,765 rows. A retuned version of the heuristic baseline reaches 50.5% (severity) and 39.3% (stage), so the trained models still lead.

## Limitations

- **Path prediction does not yet beat the baseline.** On held-out groups the model scores F1 0.32 against 0.56 for the baseline, and calibration is also weaker. It is the main open problem.
- The stage set is small (about 560 rows, drawn from ATT&CK technique descriptions), so those numbers should be read with caution.
- Severity LOW and CRITICAL classes have low precision (0.37 and 0.45) despite good recall.
- Dark-web evaluation uses a very small hand-labelled sample.

## Roadmap

- Improve path prediction (richer transition features, sequence models) and re-evaluate.
- Grow the labelled kill-chain set beyond ATT&CK descriptions.
- Add spaCy NER alongside regex extraction and publish the regex-vs-NER comparison (O2).
- Fall back to the mock corpus when Tor is unavailable (O5).
- Build the REST API, dashboard, and database layer (O7).
- Add a `requirements.txt` and basic automated tests.

## Project documents

- Software Requirements Specification (August 2026)
- Synopsis (August 2026)
- System Design documentation: DFDs, ER diagrams, architecture, use cases, sequence and execution flow (September 2026)

## Authors

Atishay Choudhary and Janvi Kushwaha, under the guidance of Dr. Dileep Kumar Singh, Jagran Lakecity University.