# IncidentLens — alert correlation & root-cause hypotheses

Groups noisy alerts into incidents, ranks the likely originating service, and shows the evidence.
Read-only: it never touches production systems and needs no credentials. All demo data is **synthetic**.

## Architecture
```
 React + TS + Tailwind + Recharts  --REST /api-->  FastAPI (backend/main.py)  -->  SQLite (incidentlens.db)
   Overview, Alerts, Incidents                     |- CSV validation (Pandas)         alerts, deps,
   RCA, Dependency map, History, Settings          |- Correlation engine              settings, inc_status
                                                   |- Root-cause ranking
                                                   '- Redaction of emails / IPs / secrets on output
```

## Run
```bash
# 1. backend (http://localhost:8000, API docs at /docs)
cd backend && python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt && uvicorn main:app --reload
# 2. frontend (http://localhost:5173, proxies /api to :8000)
cd frontend && npm install && npm run dev
```
Click **Load demo data** on the Overview page, or upload `data/sample_alerts.csv` in Alert Explorer.
CSV columns: `alert_id,timestamp,service,severity,message[,status]`; severity is info/warning/error/critical.

## How correlation works (the rule that fired is shown per alert)
Alerts are linked only when they fall within the time window (default 15 min, configurable) **and** one rule holds:
1. same service and message similarity (token Jaccard) >= threshold;
2. different services connected in the dependency graph (transitive), both >= warning;
3. different services with very similar messages (threshold + 0.3), both >= warning.
Time proximity alone never groups alerts. Groups of 2+ alerts become incidents.

## How root-cause ranking works
Each service in an incident scores: 0.30 earliest alert + 0.35 share of the incident's other services downstream of it
+ 0.10 alert volume + 0.10 max severity + 0.15 past incidents it started. If the best score is < 0.4 or no known failure
pattern matches its messages, the result is "Unknown — insufficient evidence." Verified facts (counts, timestamps) are shown
separately from the suspected cause, which is always labelled unverified. Default dependency edges are illustrative; edit them in Settings.
"Avg time to correlate" = minutes from an incident's first alert to its second.
