"""IncidentLens backend: alert ingestion, correlation, root-cause ranking. SQLite + FastAPI + Pandas."""
import io, re, sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DB = Path(__file__).parent / "incidentlens.db"
SEV = {"info": 0, "warning": 1, "error": 2, "critical": 3}
DEFAULT_DEPS = [("db-primary", "api-server"), ("redis-cache", "api-server"), ("auth-service", "api-server"),
                ("api-server", "frontend"), ("cdn", "frontend")]
app = FastAPI(title="IncidentLens")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY, ts TEXT, service TEXT, severity TEXT, message TEXT,
        status TEXT, synthetic INTEGER DEFAULT 0, incident_id TEXT, reason TEXT);
    CREATE TABLE IF NOT EXISTS deps(upstream TEXT, downstream TEXT, source TEXT, PRIMARY KEY(upstream, downstream));
    CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v REAL);
    CREATE TABLE IF NOT EXISTS inc_status(incident_id TEXT PRIMARY KEY, status TEXT);""")
    for k, v in {"window_min": 15, "similarity": 0.35}.items():
        c.execute("INSERT OR IGNORE INTO settings VALUES(?,?)", (k, v))
    if not c.execute("SELECT 1 FROM deps").fetchone():
        c.executemany("INSERT INTO deps VALUES(?,?,?)", [(u, d, "sample (illustrative)") for u, d in DEFAULT_DEPS])
    c.commit(); c.close()
init()

# ---------- helpers ----------
RED = [(re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"), "[email]"), (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "[ip]"),
       (re.compile(r"(?i)\b(token|password|secret|api[_-]?key)\s*[=:]\s*\S+"), r"\1=[redacted]")]
def redact(s):
    for p, r in RED: s = p.sub(r, s)
    return s
def pub(a): return {**{k: a[k] for k in ("alert_id", "ts", "service", "severity", "status", "synthetic", "incident_id", "reason")},
                    "message": redact(a["message"])}
def dt(s): return datetime.fromisoformat(s)
def tok(m): return {w for w in re.sub(r"[^a-z ]", " ", m.lower()).split() if len(w) > 2}
def jac(a, b): return len(a & b) / len(a | b) if a | b else 0.0
def settings(c): return {r["k"]: r["v"] for r in c.execute("SELECT * FROM settings")}
def edges(c): return [dict(r) for r in c.execute("SELECT * FROM deps")]
def reach(es):
    g = {}
    for e in es: g.setdefault(e["upstream"], set()).add(e["downstream"])
    def walk(n, seen):
        for m in g.get(n, ()):
            if m not in seen: seen.add(m); walk(m, seen)
        return seen
    return {n: walk(n, set()) for n in set(g) | {e["downstream"] for e in es}}

# ---------- correlation engine ----------
def correlate(c):
    s = settings(c); win = s["window_min"] * 60; thr = s["similarity"]
    A = [dict(r) for r in c.execute("SELECT * FROM alerts ORDER BY ts")]
    R = reach(edges(c)); T = [tok(a["message"]) for a in A]; P = list(range(len(A))); why = {}
    def f(x):
        while P[x] != x: P[x] = P[P[x]]; x = P[x]
        return x
    for j, b in enumerate(A):
        for i in range(j - 1, -1, -1):
            a = A[i]; d = (dt(b["ts"]) - dt(a["ts"])).total_seconds()
            if d > win: break
            sim = jac(T[i], T[j]); both = min(SEV[a["severity"]], SEV[b["severity"]]) >= 1; gap = f"{d/60:.0f} min apart"
            sa, sb = a["service"], b["service"]
            if sa == sb and sim >= thr:
                r = f"Same service ({sb}), message similarity {sim:.2f} >= {thr}, {gap}"
            elif sa != sb and both and (sb in R.get(sa, ()) or sa in R.get(sb, ())):
                up, dn = (sa, sb) if sb in R.get(sa, ()) else (sb, sa)
                r = f"Dependency: {up} is upstream of {dn}; both >= warning; {gap}"
            elif sa != sb and both and sim >= thr + 0.3:
                r = f"Similar message across services (similarity {sim:.2f}), {gap}"
            else: continue
            P[f(i)] = f(j); why.setdefault(j, f"{r} -> linked to {a['alert_id']}")
    groups = {}
    for i in range(len(A)): groups.setdefault(f(i), []).append(i)
    c.execute("UPDATE alerts SET incident_id=NULL, reason='No correlated alert within the time window'")
    for idx in groups.values():
        if len(idx) < 2: continue
        iid = "INC-" + A[idx[0]]["alert_id"]
        for i in idx:
            c.execute("UPDATE alerts SET incident_id=?, reason=? WHERE alert_id=?",
                      (iid, why.get(i, "Earliest alert in group; later alerts link back to it"), A[i]["alert_id"]))
    c.commit()

def incidents(c):
    A = [dict(r) for r in c.execute("SELECT * FROM alerts WHERE incident_id IS NOT NULL ORDER BY ts")]
    latest = c.execute("SELECT MAX(ts) FROM alerts").fetchone()[0]
    st = {r[0]: r[1] for r in c.execute("SELECT * FROM inc_status")}; G = {}
    for a in A: G.setdefault(a["incident_id"], []).append(a)
    out = []
    for k, v in G.items():
        end = v[-1]["ts"]; old = (dt(latest) - dt(end)).total_seconds() > 6 * 3600
        out.append(dict(id=k, start=v[0]["ts"], end=end, severity=max((x["severity"] for x in v), key=SEV.get),
                        alert_count=len(v), services=sorted({x["service"] for x in v}),
                        status=st.get(k, "resolved" if old else "open"),
                        detect_min=round((dt(v[1]["ts"]) - dt(v[0]["ts"])).total_seconds() / 60, 1),
                        synthetic=bool(v[0]["synthetic"]), _alerts=v))
    return sorted(out, key=lambda x: x["start"], reverse=True)

# ---------- root-cause ranking ----------
CAUSES = [(r"slow quer|pool|deadlock|replication|lock", "Database performance degradation (slow queries / connection-pool exhaustion)",
           ["Review the slow-query log and active sessions on {s}", "Check connection-pool usage and recent deploys or schema changes",
            "Check replication lag and storage I/O on {s}"]),
          (r"memory|oom|evict", "Memory pressure or cache eviction", ["Check memory/eviction graphs for {s}", "Look for recent traffic or key-size changes"]),
          (r"cpu|load", "CPU saturation", ["Check CPU and run-queue metrics for {s}", "Look for runaway jobs or traffic spikes"]),
          (r"disk|storage|space", "Disk capacity exhaustion", ["Check free space and growth rate on {s}", "Identify large or fast-growing files/logs"]),
          (r"timeout|50\d|latency|error rate", "Service degradation producing downstream errors",
           ["Check {s} health, saturation and recent deploys", "Inspect its own upstream dependencies"])]

def rca(c, inc, allinc):
    R = reach(edges(c)); v = inc["_alerts"]; svcs = inc["services"]
    by = {s: [a for a in v if a["service"] == s] for s in svcs}
    t0 = dt(v[0]["ts"]); span = max((dt(v[-1]["ts"]) - t0).total_seconds(), 1); hist = {}
    for o in allinc:
        if o["id"] != inc["id"] and o["alert_count"] >= 3:
            s0 = o["_alerts"][0]["service"]; hist[s0] = hist.get(s0, 0) + 1
    ranking = []
    for s, al in by.items():
        early = 1 - (dt(al[0]["ts"]) - t0).total_seconds() / span
        down = sorted(x for x in svcs if x != s and x in R.get(s, ()))
        cov = len(down) / (len(svcs) - 1) if len(svcs) > 1 else 0
        score = .30 * early + .35 * cov + .10 * len(al) / len(v) + .10 * max(SEV[a["severity"]] for a in al) / 3 + .15 * min(hist.get(s, 0), 2) / 2
        ranking.append(dict(service=s, score=round(score, 2), first_alert=al[0]["ts"], alert_count=len(al), downstream=down,
                            history_matches=hist.get(s, 0), alerts=al))
    ranking.sort(key=lambda x: -x["score"]); top = ranking[0]; s = top["service"]
    text = " ".join(a["message"].lower() for a in top["alerts"]); cause, steps_ = None, []
    for pat, desc, steps in CAUSES:
        if re.search(pat, text): cause, steps_ = desc, [x.format(s=s) for x in steps]; break
    unknown = top["score"] < 0.4 or cause is None
    ev = [dict(alert_id=a["alert_id"], ts=a["ts"], service=a["service"], message=redact(a["message"])) for a in top["alerts"][:8]]
    facts = [f"{len(v)} alerts across {len(svcs)} service(s) between {v[0]['ts']} and {v[-1]['ts']}",
             f"First alert from {s} at {top['first_alert']} ({top['alerts'][0]['alert_id']})"]
    if top["downstream"]: facts.append(f"Dependency map lists {', '.join(top['downstream'])} downstream of {s} (configured/illustrative edges)")
    if top["history_matches"]: facts.append(f"{s} started {top['history_matches']} other recorded incident(s)")
    return dict(origin=None if unknown else s, root_cause="Unknown — insufficient evidence." if unknown else cause,
                confidence=0.0 if unknown else top["score"],
                level="none" if unknown else "high" if top["score"] >= .7 else "medium" if top["score"] >= .5 else "low",
                verified_facts=facts,
                suspected=[] if unknown else [dict(text=f"{cause} originating at {s}", status="suspected — not verified",
                           basis=f"{s} alerted first and {len(top['downstream'])} affected service(s) depend on it",
                           evidence_ids=[e["alert_id"] for e in ev])],
                evidence=ev, downstream=top["downstream"] if not unknown else [],
                steps=[] if unknown else steps_ + ["Verify against logs/metrics before acting; this is a hypothesis"],
                ranking=[{k: x[k] for k in ("service", "score", "first_alert", "alert_count", "history_matches")} for x in ranking])

def detail(c, iid):
    allinc = incidents(c); inc = next((i for i in allinc if i["id"] == iid), None)
    if not inc: raise HTTPException(404, "Incident not found")
    r = rca(c, inc, allinc); es = [e for e in edges(c) if e["upstream"] in inc["services"] and e["downstream"] in inc["services"]]
    roles = {s: ("origin" if s == r["origin"] else "affected" if r["origin"] and s in r["downstream"] else "other") for s in inc["services"]}
    return {**{k: v for k, v in inc.items() if k != "_alerts"}, "alerts": [pub(a) for a in inc["_alerts"]], "rca": r, "graph": dict(edges=es, roles=roles)}

# ---------- API ----------
@app.get("/api/stats")
def stats():
    c = db(); df = pd.read_sql("SELECT ts, service, severity FROM alerts", c); inc = incidents(c)
    if df.empty: return dict(total=0, incidents=0, critical=0, duplicates=0, avg_detect=None, volume=[], by_severity=[], top_services=[])
    df["ts"] = pd.to_datetime(df["ts"]); vol = df.set_index("ts").resample("1h").size()
    sev = pd.Series([i["severity"] for i in inc]).value_counts() if inc else pd.Series(dtype=int)
    return dict(total=len(df), incidents=len(inc), critical=sum(i["severity"] == "critical" for i in inc),
                duplicates=sum(i["alert_count"] - 1 for i in inc),
                avg_detect=round(sum(i["detect_min"] for i in inc) / len(inc), 1) if inc else None,
                volume=[dict(t=k.strftime("%d %b %H:00"), alerts=int(n)) for k, n in vol.items()],
                by_severity=[dict(severity=k, count=int(sev.get(k, 0))) for k in SEV],
                top_services=[dict(service=k, alerts=int(n)) for k, n in df.service.value_counts().head(7).items()])

SORTS = {"ts": "ts", "alert_id": "alert_id", "service": "service", "status": "status",
         "severity": "CASE severity WHEN 'info' THEN 0 WHEN 'warning' THEN 1 WHEN 'error' THEN 2 ELSE 3 END"}
@app.get("/api/alerts")
def alerts(q: str = "", severity: str = "", service: str = "", status: str = "", sort: str = "ts", order: str = "desc",
           page: int = 1, page_size: int = Query(15, le=100)):
    c = db(); w, p = [], []
    if q: w.append("(message LIKE ? OR alert_id LIKE ? OR service LIKE ?)"); p += [f"%{q}%"] * 3
    for col, val in (("severity", severity), ("service", service), ("status", status)):
        if val: w.append(f"{col}=?"); p.append(val)
    where = "WHERE " + " AND ".join(w) if w else ""
    total = c.execute(f"SELECT COUNT(*) FROM alerts {where}", p).fetchone()[0]
    rows = c.execute(f"SELECT * FROM alerts {where} ORDER BY {SORTS.get(sort, 'ts')} {'ASC' if order == 'asc' else 'DESC'} LIMIT ? OFFSET ?",
                     p + [page_size, (max(page, 1) - 1) * page_size]).fetchall()
    return dict(items=[pub(dict(r)) for r in rows], total=total, pages=max(1, -(-total // page_size)),
                services=[r[0] for r in c.execute("SELECT DISTINCT service FROM alerts ORDER BY 1")])

@app.post("/api/alerts/upload")
async def upload(file: UploadFile = File(...)):
    if not (file.filename or "").lower().endswith(".csv"): raise HTTPException(400, "Please upload a .csv file.")
    raw = await file.read()
    if len(raw) > 5_000_000: raise HTTPException(400, "File is larger than 5 MB.")
    try: df = pd.read_csv(io.BytesIO(raw), dtype=str).fillna("")
    except Exception as e: raise HTTPException(400, f"Could not read CSV: {e}")
    df.columns = [x.strip().lower() for x in df.columns]
    need = ["alert_id", "timestamp", "service", "severity", "message"]
    miss = [x for x in need if x not in df.columns]
    if miss: raise HTTPException(400, f"Missing required column(s): {', '.join(miss)}. Expected: {', '.join(need)} (+ optional status).")
    if df.empty: raise HTTPException(400, "The CSV has no data rows.")
    ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True); errs = []
    for i, r in df.iterrows():
        n = i + 2
        if pd.isna(ts[i]): errs.append(f"Row {n}: invalid timestamp '{r['timestamp']}' (use ISO format, e.g. 2026-10-27T14:03:00)")
        if r["severity"].strip().lower() not in SEV: errs.append(f"Row {n}: severity '{r['severity']}' must be one of {', '.join(SEV)}")
        for col in ("alert_id", "service", "message"):
            if not r[col].strip(): errs.append(f"Row {n}: {col} is empty")
    if df["alert_id"].duplicated().any(): errs.append("Duplicate alert_id values: " + ", ".join(df[df["alert_id"].duplicated()]["alert_id"][:5]))
    if errs: raise HTTPException(422, dict(message=f"Validation failed ({len(errs)} problem(s)). Nothing was imported.", errors=errs[:20]))
    c = db()
    for i, r in df.iterrows():
        c.execute("INSERT OR REPLACE INTO alerts(alert_id,ts,service,severity,message,status,synthetic) VALUES(?,?,?,?,?,?,0)",
                  (r["alert_id"].strip(), ts[i].tz_localize(None).strftime("%Y-%m-%dT%H:%M:%S"), r["service"].strip(),
                   r["severity"].strip().lower(), r["message"].strip(), r.get("status", "").strip() or "open"))
    correlate(c); return dict(imported=len(df))

@app.post("/api/correlate")
def run_correlate(): c = db(); correlate(c); return dict(incidents=len(incidents(c)))

@app.get("/api/incidents")
def list_incidents():
    c = db(); allinc = incidents(c); out = []
    for i in allinc:
        r = rca(c, i, allinc)
        out.append({**{k: v for k, v in i.items() if k != "_alerts"}, "origin": r["origin"], "root_cause": r["root_cause"],
                    "confidence": r["confidence"], "level": r["level"]})
    return out

@app.get("/api/incidents/{iid}")
def incident(iid: str): return detail(db(), iid)

@app.post("/api/incidents/{iid}/analyze")
def analyze(iid: str): return detail(db(), iid)["rca"]

class StatusBody(BaseModel): status: str
@app.patch("/api/incidents/{iid}")
def set_status(iid: str, b: StatusBody):
    if b.status not in ("open", "investigating", "resolved"): raise HTTPException(400, "Status must be open, investigating or resolved.")
    c = db(); detail(c, iid); c.execute("INSERT OR REPLACE INTO inc_status VALUES(?,?)", (iid, b.status)); c.commit(); return dict(ok=True)

class Edge(BaseModel): upstream: str; downstream: str
@app.get("/api/dependencies")
def get_deps(): return edges(db())
@app.put("/api/dependencies")
def put_deps(es: list[Edge]):
    c = db(); c.execute("DELETE FROM deps")
    for e in es:
        if e.upstream.strip() and e.downstream.strip() and e.upstream != e.downstream:
            c.execute("INSERT OR IGNORE INTO deps VALUES(?,?,?)", (e.upstream.strip(), e.downstream.strip(), "user-defined"))
    correlate(c); return edges(c)

class SettingsBody(BaseModel): window_min: float; similarity: float
@app.get("/api/settings")
def get_settings(): return settings(db())
@app.put("/api/settings")
def put_settings(b: SettingsBody):
    if not (1 <= b.window_min <= 240) or not (0 <= b.similarity <= 1): raise HTTPException(400, "Window must be 1-240 minutes and similarity 0-1.")
    c = db(); c.execute("REPLACE INTO settings VALUES('window_min',?)", (b.window_min,)); c.execute("REPLACE INTO settings VALUES('similarity',?)", (b.similarity,))
    correlate(c); return settings(c)

@app.delete("/api/data")
def clear():
    c = db(); c.execute("DELETE FROM alerts"); c.execute("DELETE FROM inc_status"); c.commit(); return dict(ok=True)

MAIN = [(0, "db-primary", "warning", "Slow query detected: SELECT on orders took 1850ms"), (1, "db-primary", "error", "Slow query detected: SELECT on orders took 4210ms"),
        (2, "db-primary", "error", "Slow query detected: UPDATE on inventory took 5100ms"), (3, "db-primary", "critical", "Connection pool exhausted: 100/100 connections in use"),
        (5, "db-primary", "error", "Replication lag 35s on db-replica"), (7, "db-primary", "critical", "Slow query detected: SELECT on orders took 9800ms"),
        (3, "api-server", "warning", "Request timeout calling db-primary after 30000ms"), (4, "api-server", "error", "HTTP 504 rate 12% on /orders"),
        (6, "api-server", "error", "Request timeout calling db-primary after 30000ms"), (8, "api-server", "critical", "HTTP 504 rate 41% on /orders"),
        (9, "api-server", "error", "Worker threads saturated waiting on upstream"), (5, "frontend", "warning", "Failed to fetch /api/orders: 504 Gateway Timeout"),
        (8, "frontend", "error", "Checkout page load time above 8s"), (10, "frontend", "error", "JS error rate spike: Failed to fetch"),
        (12, "frontend", "critical", "Checkout availability below SLO: 97.1%")]
PAST = [(0, "redis-cache", "warning", "Memory usage at 94%, evictions rising"), (2, "redis-cache", "error", "Eviction spike 12000 keys/s"),
        (4, "api-server", "warning", "Cache miss ratio 80%, p95 latency 2100ms"), (6, "api-server", "error", "Request latency p95 3400ms"),
        (8, "frontend", "warning", "Slow page load above 6s")]
NOISE = [(-300, "batch-worker", "warning", "Disk usage 82% on /data"), (-180, "cdn", "info", "TLS certificate expires in 14 days"),
         (-90, "auth-service", "warning", "Login failed for user ops@acme.io from 10.2.3.4 password=hunter2")]

@app.post("/api/demo")
def demo():
    c = db(); c.execute("DELETE FROM alerts"); c.execute("DELETE FROM inc_status")
    now = datetime.now().replace(second=0, microsecond=0); ev = []
    for base, rows, st in ((-120, MAIN, "open"), (-1560, PAST, "resolved"), (0, NOISE, "open")):
        ev += [(now + timedelta(minutes=base + o), s, sv, m, st) for o, s, sv, m in rows]
    ev.sort()
    for n, (t, s, sv, m, st) in enumerate(ev, 1):
        c.execute("INSERT INTO alerts(alert_id,ts,service,severity,message,status,synthetic) VALUES(?,?,?,?,?,?,1)",
                  (f"ALR-{n:04d}", t.strftime("%Y-%m-%dT%H:%M:%S"), s, sv, m, st))
    correlate(c); return dict(loaded=len(ev), synthetic=True)
