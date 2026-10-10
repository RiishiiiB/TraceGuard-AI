# TraceGuard AI — Explainable Cyber Incident Investigator

Academic prototype (CSE final-year project). Upload authentication logs, detect suspicious login
activity with **deterministic, explainable rules**, correlate findings into **incidents**, and review the
exact evidence behind every risk score. There is no machine learning or LLM in the engine.

## Run it

Requires Python 3.12+ and Node 20+.

```bash
# 1. Backend (terminal 1)
cd backend
python -m venv .venv
.venv\Scripts\activate            # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000

# 2. Frontend (terminal 2)
cd frontend
npm install
npm run dev                       # open http://localhost:5173

# 3. Tests
cd backend
python -m pytest -q
```

Click **Load demo data** to run the synthetic dataset, or **Upload CSV**. The dev server proxies `/api`
to port 8000; no sign-in or API keys.

## CSV schema

| column | format |
|---|---|
| `timestamp` | ISO 8601 (`2025-03-10T14:02:10Z`); no timezone ⇒ treated as UTC |
| `username` | account name |
| `source_ip` | IPv4 / IPv6 |
| `event_type` | `login`, `logout`, `password_reset` |
| `status` | `success`, `failure` |

Sample file: `sample_data/traceguard_sample_auth_log.csv` (also `GET /api/demo-data`). It is **synthetic**:
attacker addresses are RFC 5737 documentation ranges. Limits: 5 MB, 20,000 rows. Malformed rows are
skipped and counted; exact duplicates are removed.

## How it works

| Module (`backend/app/`) | Role |
|---|---|
| `config.py` | all thresholds/windows in one place |
| `analyzer.py` | CSV validation → events → pipeline → report |
| `detector.py` | rules R001–R005, evidence + explanation text |
| `scoring.py` | transparent 0–100 heuristic |
| `correlator.py` | findings → incidents |
| `main.py` | FastAPI endpoints, in-memory result store |

**Rules** (defaults): R001 ≥5 failed logins from one IP in 10 min · R002 ≥5 failures against one account in
10 min · R003 ≥5 failures then a success for that account within 15 min · R004 successful login 00:00–06:00 UTC ·
R005 ≥4 distinct accounts failing from one IP in 15 min.

**Scoring.** Finding = rule base (R001 25, R002 25, R003 35, R004 15, R005 30) + volume bonus (+2 per unit above
threshold, cap +20) + rule modifiers (e.g. R003 success from a failing IP +15), capped at 100.
Incident = highest finding score + corroboration (+5 per extra distinct rule, cap 15) + event volume
(+1 per 10 *unique* events, cap 10) + extra accounts (+1 each, cap 10). Bands: LOW <30, MEDIUM <55, HIGH <80,
CRITICAL ≥80. Events matched by several rules are counted once. The score is a prioritisation heuristic, **not a
probability of compromise**.

**Correlation.** Two findings join the same incident if they share a source IP or username **and** their time
ranges are ≤30 min apart; links are transitive (union-find). Unflagged events sharing the incident's IP/account
nearby are shown as dimmed "context" in the timeline but never scored.

## API

`GET /api/health` · `GET /api/demo-data` (sample CSV) · `POST /api/analyze/demo` · `POST /api/analyze`
(multipart `file`) · `GET /api/rules` · `GET /api/analysis/{id}` · `GET /api/analysis/{id}/report` (JSON download).
Results live in memory (last 20) and vanish on backend restart.

## Demo scenarios (synthetic)

| Incident | What it shows | Rules | Result |
|---|---|---|---|
| admin brute force → success → password reset | compromise sequence | R001 R002 R003 | CRITICAL 81 |
| one IP failing against 9 accounts | password spraying | R001 R005 | HIGH 55 |
| svc_backup hit from 3 IPs | distributed attack on one account | R002 | MEDIUM 37 |
| finance_lead login at 02:47 UTC, new IP | off-hours login | R004 | LOW 25 |

Also in the data: single typos and a 3-failures-then-success "near miss" (`bob`) that correctly raise nothing.

## Known limitations

- Heuristic thresholds, not tuned on real traffic; shared NAT, service accounts and shift workers cause false positives.
- Unusual hours are evaluated in UTC for every user; there is no per-user behavioural baseline.
- No IP geolocation, threat-intelligence lookups or attribution. No persistence, auth, or streaming.
- Only `login` events feed the failure/success rules; failed `password_reset` events are ignored.

## Viva cheat-sheet

- **Why rules, not ML?** Every alert must be explainable and testable; the explanation text is assembled from the
  actual matched events, so nothing is "AI-generated guesswork".
- **How do you avoid false alarms?** Thresholds + windows, one finding per burst, and each finding lists plausible
  benign causes. Normal activity and near-misses are covered by tests.
- **How is double counting avoided?** Incident scores use the union of event IDs and a capped corroboration bonus.
- **What would you improve?** Per-user baselines, configurable timezones, persistence, and evaluation on public datasets.
