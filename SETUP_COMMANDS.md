# CDKCIAE: set-up and command reference

Commands are for **Windows PowerShell**, run from the project folder (the one
containing `backend`, `engine`, `frontend`). On Linux or macOS use `export NAME=value`
instead of `$env:NAME = "value"`, and `/` instead of `\`.

Times are rough, on an ordinary laptop.

---------------------------------------------------------------------------
## 1. One-time installation on a new computer

Needs: **Python 3.12 or newer**. Node.js is needed only if you change the frontend.

```powershell
# 1.1  (optional but recommended) isolated Python environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # Linux/macOS: source .venv/bin/activate

# 1.2  install the packages
python -m pip install --upgrade pip
pip install -r requirements.txt

# 1.3  language model for named-entity recognition (optional; regex-only without it)
python -m spacy download en_core_web_sm

# 1.4  (optional) XGBoost classifier
pip install xgboost
```

---------------------------------------------------------------------------
## 2. Create the database and load all data

Everything lives in one database file, `backend\db.sqlite3` (change it with
`$env:CDKCIAE_DB = "C:\path\file.sqlite3"`, set before every command below).

```powershell
# 2.1  create all tables (also the user, session and admin tables)
python .\backend\manage.py migrate

# 2.2  load reference data, build the labelled sets and train both classifiers
#      (about 2 minutes). Reads the files in datasets\ once; the project never
#      reads them again.
python .\backend\manage.py bootstrap --from-files
#      other classifiers:  --model rf | svm | xgboost      (default: logreg)
```

`bootstrap` is the same as running these three steps by hand:

```powershell
python .\backend\manage.py sync_reference --from-files     # NVD, CISA KEV, ATT&CK, historical incidents, mock pages, sources
python .\backend\manage.py build_labelled                  # severity (88k rows) + kill-chain (559 rows) sets
python -m engine.ml.classifier --task severity --model logreg
python -m engine.ml.classifier --task stage    --model logreg
```

(If `python -m ...` says "No module named engine", run it as
`$env:PYTHONPATH = "."` first.)

### 2.3  Refresh the reference data from the internet (optional, later)

```powershell
$env:NVD_API_KEY = "your-key"        # optional; without it NVD downloads are slow
python .\backend\manage.py sync_reference --pull kev,mitre,nvd --nvd-years 2
python .\backend\manage.py build_labelled
python -m engine.ml.classifier --task severity
python -m engine.ml.classifier --task stage
```

Historical incidents and mock pages are loaded only by `--from-files`.

---------------------------------------------------------------------------
## 3. Users, sources, old jobs

```powershell
# 3.1  first administrator (asks for name and password)
python .\backend\manage.py createsuperuser

# 3.2  load your live crawl sources (checked before anything is written)
python .\backend\manage.py import_sources .\config\dw_sources.json
python .\backend\manage.py import_sources .\config\dw_sources.json --disable-missing

# 3.3  give collections made before users existed to one user
python .\backend\manage.py assign_jobs <username>
```

Ordinary users can create their own account on the sign-in page. Staff manage
users and sources at http://localhost:8000/admin/ .

---------------------------------------------------------------------------
## 4. Run the application

```powershell
# options (all optional; they last for this window only)
$env:CDKCIAE_REQUIRE_LOGIN = "1"          # users must sign in
$env:CDKCIAE_ALLOW_SIGNUP  = "0"          # stop visitors creating accounts (default "1")
$env:CDKCIAE_API_TOKEN     = "long-random-text"   # bearer token for scripts
$env:CDKCIAE_SECRET_KEY    = "long-random-text"   # set this for anything beyond a demo
$env:CDKCIAE_TOR_HOST      = "127.0.0.1"  # live mode: where Tor listens
$env:CDKCIAE_TOR_PORT      = "9050"       # 9150 if you use Tor Browser

python .\backend\manage.py runserver
```

Open http://127.0.0.1:8000/ . Live mode needs Tor running (see
`docs\TOR_DEPLOYMENT.md`); mock mode needs nothing.

---------------------------------------------------------------------------
## 5. Evaluation (numbers for the report)

Run after section 2. Every result is stored in the database; the dashboard's
Evaluation tab shows the latest.

```powershell
$env:PYTHONPATH = "."

# 5.1  (optional, several minutes) search for better classifier settings
python -m engine.evaluation.tuning
python -m engine.evaluation.tuning --clear        # go back to the defaults

# 5.2  classifier metrics: accuracy, macro-F1, confusion matrices, baseline comparison
python -m engine.evaluation.evaluate --model logreg

# 5.3  attack-path prediction metrics (edge AUC / Brier, path overlap)
python -m engine.evaluation.path_evaluation

# 5.4  CVSS v3.1 calculator check against NVD scores
python -m engine.evaluation.cvss_validation

# 5.5  the same evaluation as the dashboard's "Run evaluation" button
python .\backend\manage.py run_evaluation --model logreg
```

---------------------------------------------------------------------------
## 6. Validation on real dark-web text (needs your hand labels)

These need collected text, so first run a few **live** collections (section 4);
on a new database there is nothing to sample yet.

```powershell
$env:PYTHONPATH = "."

# 6.1  sample snippets from what the crawler collected
python -m engine.evaluation.darkweb_validation export

# 6.2  label them: easiest in the dashboard (Label tab). Or on the command line:
python -m engine.evaluation.darkweb_validation label <id> severity=HIGH stage=Delivery

# 6.3  score the trained models on your labels (aim for 100+ labelled snippets)
python -m engine.evaluation.darkweb_validation score

# Named-entity recognition: regex vs spaCy (needs step 1.3)
python -m engine.evaluation.ner_evaluation export
python -m engine.evaluation.ner_evaluation label <id> emails=a@b.c cves=CVE-2024-0001
python -m engine.evaluation.ner_evaluation score
```

---------------------------------------------------------------------------
## 7. Checks

```powershell
python .\backend\manage.py check          # configuration
python .\backend\manage.py test core      # 45 automated tests (about 10 seconds)
```

---------------------------------------------------------------------------
## 8. Only if you change the frontend

The built dashboard is already in `backend\core\frontend_dist`. To rebuild:

```powershell
cd frontend
npm install
npm run build        # writes into ..\backend\core\frontend_dist (old files are removed)
cd ..
```

For live reloading while editing: `npm run dev` in `frontend` (port 5173) with
the Django server running on port 8000.

---------------------------------------------------------------------------
## 9. Start again from nothing

```powershell
Remove-Item .\backend\db.sqlite3
python .\backend\manage.py migrate
python .\backend\manage.py bootstrap --from-files
python .\backend\manage.py createsuperuser
```

## Order at a glance

```
pip install -r requirements.txt  ->  python -m spacy download en_core_web_sm
migrate  ->  bootstrap --from-files  ->  createsuperuser  ->  import_sources
[tuning]  ->  evaluate  ->  path_evaluation  ->  cvss_validation  ->  run_evaluation
runserver  ->  live collections  ->  darkweb_validation / ner_evaluation (label, score)
```
<!-- python .\backend\manage.py import_sources .\config\dw_sources.json -->