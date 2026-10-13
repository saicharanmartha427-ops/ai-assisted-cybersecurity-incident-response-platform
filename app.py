import csv
import io
import json
import math
import os
import re
import secrets
import sqlite3
from dotenv import load_dotenv
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("JWT_SECRET") or secrets.token_urlsafe(32)
if not os.getenv("JWT_SECRET"):
    app.logger.warning("JWT_SECRET is not configured; a temporary random secret is being used. Set JWT_SECRET in backend/.env.")
CORS(app, resources={r"/api/*": {"origins": os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")}})

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("SQLITE_DB", os.path.join(BASE_DIR, "cyber_ir.db"))
ALLOWED_SEVERITIES = {"Critical", "High", "Medium", "Low"}
ALLOWED_STATUSES = {"Active", "Investigating", "Contained", "Resolved"}


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso_now():
    return utc_now().isoformat().replace("+00:00", "Z")


def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = db_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('Admin','Analyst')),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            external_id TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Active',
            recommendation TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            source TEXT NOT NULL DEFAULT 'Manual',
            details TEXT,
            anomaly_score REAL DEFAULT 0,
            detected_at TEXT NOT NULL,
            responded_at TEXT,
            resolved_at TEXT,
            created_by TEXT
        );
        CREATE TABLE IF NOT EXISTS incident_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            result TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            port INTEGER,
            bytes REAL DEFAULT 0,
            failed_logins REAL DEFAULT 0,
            requests_per_minute REAL DEFAULT 0,
            event_type TEXT DEFAULT 'Network Telemetry',
            raw_data TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS playbooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            action TEXT NOT NULL,
            description TEXT,
            enabled INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            created_at TEXT NOT NULL,
            incident_count INTEGER DEFAULT 0,
            mttd REAL DEFAULT 0,
            mttr REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            details TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )

    # Lightweight schema migration for the earlier prototype database.
    existing = {row[1] for row in conn.execute("PRAGMA table_info(incidents)").fetchall()}
    migrations = {
        "destination_ip": "TEXT", "source": "TEXT NOT NULL DEFAULT 'Manual'",
        "anomaly_score": "REAL DEFAULT 0", "resolved_at": "TEXT", "created_by": "TEXT"
    }
    for column, definition in migrations.items():
        if column not in existing:
            conn.execute(f"ALTER TABLE incidents ADD COLUMN {column} {definition}")

    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO users(username,display_name,password_hash,role,created_at) VALUES (?,?,?,?,?)",
            [
                ("admin", "SOC Administrator", generate_password_hash("Admin@123"), "Admin", iso_now()),
                ("analyst", "Security Analyst", generate_password_hash("Analyst@123"), "Analyst", iso_now()),
            ],
        )

    if conn.execute("SELECT COUNT(*) FROM playbooks").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO playbooks(name, action, description, enabled) VALUES (?, ?, ?, ?)",
            [
                ("Block IP", "BLOCK_IP", "Block the malicious source IP at the perimeter firewall.", 1),
                ("Quarantine File", "QUARANTINE_FILE", "Isolate a suspicious file from the affected endpoint.", 1),
                ("Notify Admin", "NOTIFY_ADMIN", "Notify the SOC administrator and escalate the incident.", 1),
            ],
        )

    defaults = {"ai_sensitivity": "18", "platform_name": "CyberGuard AI Response Platform"}
    for key, value in defaults.items():
        conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (key, value))

    if conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 0:
        now = utc_now()
        demo = [
            ("INC-1001", "Brute Force", "Critical", now - timedelta(minutes=42), now - timedelta(minutes=39), "Active", "Block IP", "185.44.91.22", "10.0.0.5", "Demo telemetry shows repeated failed authentication attempts.", 4.82),
            ("INC-1002", "Port Scan", "High", now - timedelta(hours=2), now - timedelta(hours=1, minutes=58), "Investigating", "Block IP", "45.88.12.7", "10.0.0.8", "Rapid connection attempts across privileged ports.", 3.74),
            ("INC-1003", "Anomalous Traffic", "Medium", now - timedelta(days=1, hours=3), now - timedelta(days=1, hours=2, minutes=58), "Resolved", "Notify Admin", "103.77.14.9", "10.0.0.15", "Traffic profile deviates from normal baseline.", 2.91),
            ("INC-1004", "Malware Indicator", "High", now - timedelta(days=2), now - timedelta(days=1, hours=23, minutes=57), "Resolved", "Quarantine File", "10.0.0.51", "10.0.0.21", "Endpoint telemetry matched a suspicious indicator.", 3.21),
        ]
        for ext, typ, sev, event_time, detected, status, rec, src, dst, details, score in demo:
            resolved = (detected + timedelta(minutes=8)).isoformat().replace("+00:00", "Z") if status == "Resolved" else None
            responded = (detected + timedelta(minutes=3)).isoformat().replace("+00:00", "Z") if status == "Resolved" else None
            conn.execute(
                """INSERT INTO incidents(external_id,type,severity,timestamp,status,recommendation,source_ip,destination_ip,source,details,anomaly_score,detected_at,responded_at,resolved_at,created_by)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ext, typ, sev, event_time.isoformat().replace("+00:00", "Z"), status, rec, src, dst, "Demo Seed", details, score, detected.isoformat().replace("+00:00", "Z"), responded, resolved, "system"),
            )
    conn.commit()
    conn.close()


def token_for(user):
    payload = {"sub": str(user["id"]), "username": user["username"], "role": user["role"], "exp": utc_now() + timedelta(hours=8)}
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        return jwt.decode(auth.split(" ", 1)[1], app.config["SECRET_KEY"], algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


def auth_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return jsonify({"error": "Authentication required"}), 401
            if role and user.get("role") != role and user.get("role") != "Admin":
                return jsonify({"error": "Insufficient permissions"}), 403
            request.user = user
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def audit(actor, action, target="", details=""):
    conn = db_conn()
    conn.execute("INSERT INTO audit_logs(actor,action,target,details,created_at) VALUES(?,?,?,?,?)", (actor, action, target, details, iso_now()))
    conn.commit()
    conn.close()


def parse_dt(value):
    if not value:
        return utc_now()
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"):
            try:
                return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
    return utc_now()


def incident_dict(row):
    return {k: row[k] for k in row.keys() if k not in {"created_by"}}


def playbook_dict(row):
    return {"id": row["id"], "name": row["name"], "action": row["action"], "description": row["description"], "enabled": bool(row["enabled"])}


def numeric_columns(rows, headers):
    candidates = []
    for h in headers:
        if h.lower() in {"id", "timestamp", "time", "source_ip", "destination_ip"}:
            continue
        vals = []
        ok = True
        for row in rows:
            value = (row.get(h) or "").strip()
            if not value:
                continue
            try:
                vals.append(float(value))
            except ValueError:
                ok = False
                break
        if ok and vals:
            candidates.append(h)
    return candidates


def ai_anomaly_scores(rows, numeric):
    stats = {}
    for col in numeric:
        vals = []
        for r in rows:
            try:
                vals.append(float(r.get(col, "") or 0))
            except ValueError:
                vals.append(0.0)
        mean = sum(vals) / len(vals)
        variance = sum((v - mean) ** 2 for v in vals) / max(1, len(vals))
        std = math.sqrt(variance) or 1.0
        stats[col] = (mean, std)
    scores = []
    for r in rows:
        squared = 0.0
        for col in numeric:
            try:
                value = float(r.get(col, "") or 0)
            except ValueError:
                value = 0.0
            mean, std = stats[col]
            squared += ((value - mean) / std) ** 2
        scores.append(math.sqrt(squared / max(1, len(numeric))))
    return scores


def generative_ai_status():
    """Return safe configuration status without exposing credentials."""
    return {
        "provider": os.getenv("LLM_PROVIDER", "openai-compatible"),
        "configured": bool(os.getenv("OPENAI_API_KEY", "").strip()),
        "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        "mode": "live-llm" if os.getenv("OPENAI_API_KEY", "").strip() else "rules-only",
    }


def generate_llm_incident_analysis(event, rule_summary, timeout=12):
    """Use an OpenAI-compatible Chat Completions API to explain an already-flagged event.

    The deterministic detector remains the source of the suspicious/not-suspicious decision.
    If no key is configured or the API fails, return None and keep the rule-based result.
    """
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    payload = {
        "model": model,
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": (
                "You are a cautious cybersecurity incident triage assistant. Analyze only the provided telemetry. "
                "Do not claim certainty, do not claim an action has been executed, and do not recommend destructive action. "
                "Return JSON with keys: summary (1-2 sentences), investigation_steps (array of 3 short strings), "
                "recommendation (one of Block IP, Notify Admin, Quarantine File, Investigate Further), "
                "confidence (Low, Medium, or High), limitations (short string)."
            )},
            {"role": "user", "content": json.dumps({"event": event, "deterministic_rule_summary": rule_summary})},
        ],
    }
    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
        content = result["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        allowed_recommendations = {"Block IP", "Notify Admin", "Quarantine File", "Investigate Further"}
        recommendation = parsed.get("recommendation")
        if recommendation not in allowed_recommendations:
            recommendation = "Investigate Further"
        steps = parsed.get("investigation_steps", [])
        if not isinstance(steps, list):
            steps = []
        return {
            "summary": str(parsed.get("summary", "LLM analysis returned no summary."))[:1200],
            "investigation_steps": [str(x)[:240] for x in steps[:5]],
            "recommendation": recommendation,
            "confidence": parsed.get("confidence") if parsed.get("confidence") in {"Low", "Medium", "High"} else "Low",
            "limitations": str(parsed.get("limitations", "AI output requires analyst verification."))[:500],
            "provider": os.getenv("LLM_PROVIDER", "openai-compatible"),
            "model": model,
        }
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, TypeError, IndexError) as exc:
        app.logger.warning("Generative AI enrichment failed (%s). Falling back to deterministic analysis.", type(exc).__name__)
        return None


def apply_llm_enrichment(row, severity, recommendation, details, score):
    event = {
        "timestamp": row.get("timestamp") or row.get("event_time"),
        "source_ip": row.get("source_ip"),
        "destination_ip": row.get("destination_ip"),
        "port": row.get("port"),
        "bytes": row.get("bytes"),
        "failed_logins": row.get("failed_logins"),
        "requests_per_minute": row.get("requests_per_minute"),
        "event_type": row.get("event_type", "Network Telemetry"),
    }
    llm = generate_llm_incident_analysis(event, {"severity": severity, "recommended_action": recommendation, "detector_details": details, "anomaly_score": round(float(score), 4)})
    if not llm:
        return recommendation, details, None
    enriched_details = (
        f"{details}\n\nGenerative AI analysis ({llm['model']}): {llm['summary']} "
        f"Investigation steps: {'; '.join(llm['investigation_steps']) or 'Review raw logs and validate the source.'} "
        f"Confidence: {llm['confidence']}. Limitations: {llm['limitations']}"
    )
    return llm["recommendation"], enriched_details[:4000], llm


def classify_event(row, score=0.0):
    def num(key):
        try:
            return float(row.get(key) or 0)
        except (TypeError, ValueError):
            return 0.0
    failed, rpm, bytes_ = num("failed_logins"), num("requests_per_minute"), num("bytes")
    port = int(num("port")) if str(row.get("port", "")).strip() else 0
    suspicious = score >= 2.0 or failed >= 30 or rpm >= 250 or bytes_ >= 500000
    if not suspicious:
        return False, "Low", "Notify Admin", "Normal telemetry profile."
    if failed >= 80 or rpm >= 500 or bytes_ >= 1000000:
        severity = "Critical"
    elif failed >= 30 or rpm >= 250 or port in {22, 23, 445, 3389}:
        severity = "High"
    else:
        severity = "Medium"
    typ = "Brute Force" if failed >= 30 else ("Suspicious Remote Access" if port in {22, 23, 3389} else "Anomalous Traffic")
    rec = "Block IP" if failed >= 30 or rpm >= 250 or port in {22, 23, 445, 3389} else "Notify Admin"
    details = f"Hybrid AI score {score:.2f}; security telemetry exceeded the configured anomaly baseline."
    return True, severity, rec, details


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "cyber-ir-backend", "engine": "hybrid-statistical-rules", "database": "sqlite"})


@app.get("/api/ai/status")
@auth_required()
def ai_status():
    status = generative_ai_status()
    status["note"] = ("Live Generative AI enrichment is enabled. Deterministic rules remain the detection gate." if status["configured"] else "No OPENAI_API_KEY configured; deterministic rules remain active and LLM enrichment is disabled.")
    return jsonify(status)


@app.get("/api/openapi.json")
def openapi_json():
    path = os.path.join(BASE_DIR, "openapi.json")
    with open(path, "r", encoding="utf-8") as f:
        return jsonify(json.load(f))


@app.post("/api/auth/login")
def login():
    data = request.get_json() or {}
    username, password = str(data.get("username", "")).strip(), str(data.get("password", ""))
    conn = db_conn()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid username or password"}), 401
    audit(username, "LOGIN", "auth", "Successful login")
    return jsonify({"token": token_for(user), "user": {"username": user["username"], "display_name": user["display_name"], "role": user["role"]}})


@app.get("/api/me")
@auth_required()
def me():
    return jsonify({"username": request.user["username"], "role": request.user["role"]})


@app.get("/api/incidents")
@auth_required()
def incidents():
    conn = db_conn()
    rows = conn.execute("SELECT * FROM incidents ORDER BY timestamp DESC").fetchall()
    conn.close()
    return jsonify([incident_dict(x) for x in rows])


@app.get("/api/incidents/<int:incident_id>")
@auth_required()
def incident_detail(incident_id):
    conn = db_conn()
    row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    actions = conn.execute("SELECT * FROM incident_actions WHERE incident_id=? ORDER BY created_at DESC", (incident_id,)).fetchall()
    conn.close()
    if not row:
        return jsonify({"error": "Incident not found"}), 404
    result = incident_dict(row)
    result["actions"] = [dict(x) for x in actions]
    return jsonify(result)


@app.patch("/api/incidents/<int:incident_id>")
@auth_required()
def update_incident(incident_id):
    data = request.get_json() or {}
    status = str(data.get("status", "")).strip()
    if status and status not in ALLOWED_STATUSES:
        return jsonify({"error": "Invalid incident status"}), 400
    conn = db_conn()
    row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Incident not found"}), 404
    fields, values = [], []
    if status:
        fields.append("status=?"); values.append(status)
        if status in {"Investigating", "Contained", "Resolved"} and not row["responded_at"]:
            fields.append("responded_at=?"); values.append(iso_now())
        if status == "Resolved":
            fields.append("resolved_at=?"); values.append(iso_now())
    if "recommendation" in data:
        fields.append("recommendation=?"); values.append(str(data["recommendation"]))
    if fields:
        values.append(incident_id)
        conn.execute(f"UPDATE incidents SET {','.join(fields)} WHERE id=?", values)
        conn.commit()
    updated = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    conn.close()
    audit(request.user["username"], "UPDATE_INCIDENT", updated["external_id"], json.dumps(data))
    return jsonify(incident_dict(updated))


@app.post("/api/incidents/<int:incident_id>/actions")
@auth_required()
def incident_action(incident_id):
    data = request.get_json() or {}
    action = str(data.get("action", "")).strip()
    if not action:
        return jsonify({"error": "Action is required"}), 400
    conn = db_conn()
    row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not row:
        conn.close(); return jsonify({"error": "Incident not found"}), 404
    now = iso_now()
    conn.execute("INSERT INTO incident_actions(incident_id,action,actor,result,created_at) VALUES(?,?,?,?,?)", (incident_id, action, request.user["username"], "Executed in response workflow", now))
    conn.execute("UPDATE incidents SET status='Contained', responded_at=COALESCE(responded_at, ?) WHERE id=?", (now, incident_id))
    if bool(data.get("resolve")):
        conn.execute("UPDATE incidents SET status='Resolved', resolved_at=? WHERE id=?", (now, incident_id))
    conn.commit()
    updated = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    conn.close()
    audit(request.user["username"], "EXECUTE_RESPONSE", updated["external_id"], action)
    return jsonify(incident_dict(updated))


@app.get("/api/dashboard")
@auth_required()
def dashboard():
    conn = db_conn()
    rows = conn.execute("SELECT * FROM incidents").fetchall()
    alerts = conn.execute("SELECT * FROM incidents WHERE status != 'Resolved' ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END, timestamp DESC LIMIT 6").fetchall()
    event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    active = sum(x["status"] != "Resolved" for x in rows)
    resolved = sum(x["status"] == "Resolved" for x in rows)
    sev = {s: sum(x["severity"] == s for x in rows) for s in ALLOWED_SEVERITIES}
    detection = []
    response = []
    for x in rows:
        detected = parse_dt(x["detected_at"])
        event = parse_dt(x["timestamp"])
        detection.append(max(0, (detected - event).total_seconds() / 60))
        if x["responded_at"]:
            response.append(max(0, (parse_dt(x["responded_at"]) - detected).total_seconds() / 60))
    mttd = round(sum(detection) / len(detection), 1) if detection else 0
    mttr = round(sum(response) / len(response), 1) if response else 0
    today = utc_now().date()
    trend = []
    for i in range(7):
        day = today - timedelta(days=6 - i)
        count = sum(parse_dt(x["timestamp"]).date() == day for x in rows)
        trend.append({"date": day.isoformat(), "count": count})
    return jsonify({"active": active, "resolved": resolved, "total": len(rows), "events": event_count, "avg_response": mttr, "mttd": mttd, "mttr": mttr, "severity": sev, "trend": trend, "alerts": [incident_dict(x) for x in alerts]})


@app.get("/api/events")
@auth_required()
def events():
    conn = db_conn(); rows = conn.execute("SELECT * FROM events ORDER BY event_time DESC LIMIT 100").fetchall(); conn.close()
    return jsonify([dict(x) for x in rows])


@app.post("/api/events")
@auth_required()
def create_event():
    data = request.get_json() or {}
    if not data.get("source_ip"):
        return jsonify({"error": "source_ip is required"}), 400
    try:
        row = {k: data.get(k, "") for k in ["source_ip", "destination_ip", "port", "bytes", "failed_logins", "requests_per_minute"]}
        row["event_type"] = data.get("event_type", "Network Telemetry")
        row["timestamp"] = data.get("timestamp") or iso_now()
        numeric = [k for k in ["port", "bytes", "failed_logins", "requests_per_minute"] if str(row.get(k, "")).strip() != ""]
        score = 0.0
        if numeric:
            # Compare against conservative local baselines for a single manual event.
            for key, baseline in [("failed_logins", 3), ("requests_per_minute", 60), ("bytes", 50000)]:
                try: score += abs(float(row.get(key) or 0) - baseline) / max(baseline, 1)
                except ValueError: pass
            score = min(score, 9.99)
        suspicious, severity, recommendation, details = classify_event(row, score)
        llm_analysis = None
        if suspicious:
            recommendation, details, llm_analysis = apply_llm_enrichment(row, severity, recommendation, details, score)
        conn = db_conn()
        conn.execute("INSERT INTO events(event_time,source_ip,destination_ip,port,bytes,failed_logins,requests_per_minute,event_type,raw_data,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                     (row["timestamp"], row["source_ip"], row["destination_ip"], int(float(row["port"])) if str(row["port"]).strip() else None, float(row["bytes"] or 0), float(row["failed_logins"] or 0), float(row["requests_per_minute"] or 0), row["event_type"], json.dumps(data), iso_now()))
        incident = None
        if suspicious:
            ext = f"EVT-{utc_now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2)}"
            cur = conn.execute("INSERT INTO incidents(external_id,type,severity,timestamp,status,recommendation,source_ip,destination_ip,source,details,anomaly_score,detected_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                               (ext, row["event_type"] if row["event_type"] else "Anomalous Traffic", severity, row["timestamp"], "Active", recommendation, row["source_ip"], row["destination_ip"], "Manual Event", details, score, iso_now(), request.user["username"]))
            incident = conn.execute("SELECT * FROM incidents WHERE id=?", (cur.lastrowid,)).fetchone()
        conn.commit(); conn.close()
        audit(request.user["username"], "CREATE_EVENT", row["source_ip"], "Suspicious=%s" % suspicious)
        return jsonify({"suspicious": suspicious, "score": round(score, 3), "severity": severity, "recommendation": recommendation, "generative_ai_used": bool(llm_analysis), "ai_analysis": llm_analysis, "incident": incident_dict(incident) if incident else None}), 201
    except (TypeError, ValueError) as exc:
        return jsonify({"error": f"Invalid event value: {exc}"}), 400


@app.post("/api/analyze")
@auth_required()
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "CSV file is required"}), 400
    file = request.files["file"]
    if not file.filename.lower().endswith(".csv"):
        return jsonify({"error": "Only CSV files are supported"}), 400
    try:
        text = file.read().decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
        headers = reader.fieldnames or []
        rows = [dict(r) for r in reader]
    except Exception as exc:
        return jsonify({"error": f"Could not read CSV: {exc}"}), 400
    if not rows: return jsonify({"error": "CSV contains no data rows"}), 400
    numeric = numeric_columns(rows, headers)
    if not numeric: return jsonify({"error": "CSV must contain numeric telemetry columns"}), 400
    scores = ai_anomaly_scores(rows, numeric)
    try: sensitivity = float(request.form.get("sensitivity", "0.18"))
    except ValueError: sensitivity = 0.18
    sensitivity = min(max(sensitivity, 0.05), 0.45)
    sorted_scores = sorted(scores, reverse=True)
    rank_count = max(1, math.ceil(len(rows) * sensitivity))
    cutoff = sorted_scores[min(rank_count - 1, len(sorted_scores) - 1)]
    threshold = max(2.0, cutoff)
    conn = db_conn(); created = []; normal = 0; llm_enriched = 0
    for idx, (row, score) in enumerate(zip(rows, scores)):
        suspicious, severity, recommendation, details = classify_event(row, score if score >= threshold else 0)
        if not suspicious:
            normal += 1
            # Persist normal events too: analytics should reflect all analyzed rows.
            timestamp = parse_dt(row.get("timestamp")).isoformat().replace("+00:00", "Z")
            source_ip = str(row.get("source_ip") or "Unknown")
            conn.execute("INSERT INTO events(event_time,source_ip,destination_ip,port,bytes,failed_logins,requests_per_minute,event_type,raw_data,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                         (timestamp, source_ip, row.get("destination_ip"), int(float(row["port"])) if str(row.get("port", "")).strip() else None, float(row.get("bytes") or 0), float(row.get("failed_logins") or 0), float(row.get("requests_per_minute") or 0), "CSV Telemetry", json.dumps(row), iso_now()))
            continue
        source_ip = str(row.get("source_ip") or "Unknown")
        llm_analysis = None
        if llm_enriched < 5:
            recommendation, details, llm_analysis = apply_llm_enrichment(row, severity, recommendation, details, score)
            if llm_analysis:
                llm_enriched += 1
        timestamp = parse_dt(row.get("timestamp")).isoformat().replace("+00:00", "Z")
        ext = f"AI-{utc_now().strftime('%Y%m%d%H%M%S')}-{idx}"
        # Prevent duplicates on repeat uploads by including source/timestamp/index in raw key.
        cur = conn.execute("INSERT INTO incidents(external_id,type,severity,timestamp,status,recommendation,source_ip,destination_ip,source,details,anomaly_score,detected_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (ext, "Brute Force" if float(row.get("failed_logins") or 0) >= 30 else "Anomalous Traffic", severity, timestamp, "Active", recommendation, source_ip, row.get("destination_ip"), "CSV AI Analysis", details, round(score, 4), iso_now(), request.user["username"]))
        created.append(conn.execute("SELECT * FROM incidents WHERE id=?", (cur.lastrowid,)).fetchone())
        conn.execute("INSERT INTO events(event_time,source_ip,destination_ip,port,bytes,failed_logins,requests_per_minute,event_type,raw_data,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                     (timestamp, source_ip, row.get("destination_ip"), int(float(row["port"])) if str(row.get("port", "")).strip() else None, float(row.get("bytes") or 0), float(row.get("failed_logins") or 0), float(row.get("requests_per_minute") or 0), "CSV Telemetry", json.dumps(row), iso_now()))
    conn.commit(); conn.close()
    audit(request.user["username"], "ANALYZE_CSV", file.filename, f"rows={len(rows)}, suspicious={len(created)}")
    return jsonify({"rows_analyzed": len(rows), "suspicious": len(created), "normal": normal, "numeric_features": numeric, "engine": "hybrid-statistical-rules", "generative_ai_configured": generative_ai_status()["configured"], "generative_ai_enriched": llm_enriched, "incidents": [incident_dict(x) for x in created], "preview": rows[:25]})


@app.get("/api/playbooks")
@auth_required()
def playbooks():
    conn = db_conn(); rows = conn.execute("SELECT * FROM playbooks ORDER BY id ASC").fetchall(); conn.close()
    return jsonify([playbook_dict(x) for x in rows])


@app.post("/api/playbooks")
@auth_required("Admin")
def create_playbook():
    data = request.get_json() or {}
    name = str(data.get("name", "")).strip(); action = str(data.get("action", "")).strip()
    if not name or not action: return jsonify({"error": "name and action are required"}), 400
    conn = db_conn(); cur = conn.execute("INSERT INTO playbooks(name,action,description,enabled) VALUES(?,?,?,?)", (name, action, data.get("description", ""), int(bool(data.get("enabled", True))))); conn.commit(); row = conn.execute("SELECT * FROM playbooks WHERE id=?", (cur.lastrowid,)).fetchone(); conn.close()
    audit(request.user["username"], "CREATE_PLAYBOOK", name, action)
    return jsonify(playbook_dict(row)), 201


@app.put("/api/playbooks/<int:playbook_id>")
@auth_required("Admin")
def edit_playbook(playbook_id):
    data = request.get_json() or {}; fields=[]; values=[]
    for field in ("name", "action", "description", "enabled"):
        if field in data: fields.append(f"{field}=?"); values.append(int(bool(data[field])) if field == "enabled" else data[field])
    conn = db_conn(); row=conn.execute("SELECT * FROM playbooks WHERE id=?", (playbook_id,)).fetchone()
    if not row: conn.close(); return jsonify({"error":"Playbook not found"}),404
    if fields: values.append(playbook_id); conn.execute(f"UPDATE playbooks SET {','.join(fields)} WHERE id=?", values); conn.commit()
    row=conn.execute("SELECT * FROM playbooks WHERE id=?",(playbook_id,)).fetchone(); conn.close(); audit(request.user["username"],"UPDATE_PLAYBOOK",str(playbook_id),json.dumps(data)); return jsonify(playbook_dict(row))


@app.delete("/api/playbooks/<int:playbook_id>")
@auth_required("Admin")
def delete_playbook(playbook_id):
    conn=db_conn(); conn.execute("DELETE FROM playbooks WHERE id=?",(playbook_id,)); conn.commit(); conn.close(); audit(request.user["username"],"DELETE_PLAYBOOK",str(playbook_id)); return jsonify({"success":True})


@app.get("/api/reports")
@auth_required()
def reports():
    conn=db_conn(); rows=conn.execute("SELECT * FROM reports ORDER BY created_at DESC").fetchall(); conn.close(); return jsonify([dict(x) for x in rows])


def metrics():
    conn=db_conn(); rows=conn.execute("SELECT * FROM incidents").fetchall(); conn.close(); det=[]; resp=[]
    for x in rows:
        det.append(max(0,(parse_dt(x["detected_at"])-parse_dt(x["timestamp"])).total_seconds()/60))
        if x["responded_at"]: resp.append(max(0,(parse_dt(x["responded_at"])-parse_dt(x["detected_at"])).total_seconds()/60))
    return (round(sum(det)/len(det),1) if det else 0, round(sum(resp)/len(resp),1) if resp else 0)


@app.post("/api/reports")
@auth_required()
def create_report():
    mttd, mttr=metrics(); conn=db_conn(); count=conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]; title=f"Incident Summary — {utc_now().strftime('%Y-%m-%d %H:%M UTC')}"; cur=conn.execute("INSERT INTO reports(title,created_at,incident_count,mttd,mttr) VALUES(?,?,?,?,?)",(title,iso_now(),count,mttd,mttr)); conn.commit(); result={"id":cur.lastrowid,"title":title,"incident_count":count,"mttd":mttd,"mttr":mttr}; conn.close(); audit(request.user["username"],"GENERATE_REPORT",title); return jsonify(result),201


@app.get("/api/reports/export.csv")
@auth_required()
def export_csv():
    conn=db_conn(); rows=conn.execute("SELECT * FROM incidents ORDER BY timestamp DESC").fetchall(); conn.close(); output=io.StringIO(); writer=csv.writer(output); writer.writerow(["ID","Type","Severity","Timestamp","Status","Recommendation","Source IP","Destination IP","Source","Anomaly Score","Details"])
    for x in rows: writer.writerow([x["external_id"],x["type"],x["severity"],x["timestamp"],x["status"],x["recommendation"],x["source_ip"],x["destination_ip"],x["source"],x["anomaly_score"],x["details"]])
    return send_file(io.BytesIO(output.getvalue().encode()),mimetype="text/csv",as_attachment=True,download_name="incident_report.csv")


def pdf_escape(text): return str(text).replace("\\","\\\\").replace("(","\\(").replace(")","\\)").replace("\n"," ")

def make_pdf(lines):
    stream=[]; y=760
    for line in lines:
        stream.append(f"BT /F1 10 Tf 50 {y} Td ({pdf_escape(line)}) Tj ET"); y-=16
        if y<50: break
    content="\n".join(stream).encode("latin-1","replace"); objects=[b"<< /Type /Catalog /Pages 2 0 R >>",b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",b"<< /Length "+str(len(content)).encode()+b" >>\nstream\n"+content+b"\nendstream"]
    pdf=bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"); offsets=[0]
    for i,obj in enumerate(objects,1): offsets.append(len(pdf)); pdf.extend(f"{i} 0 obj\n".encode()); pdf.extend(obj); pdf.extend(b"\nendobj\n")
    xref=len(pdf); pdf.extend(f"xref\n0 {len(objects)+1}\n".encode()); pdf.extend(b"0000000000 65535 f \n");
    for off in offsets[1:]: pdf.extend(f"{off:010d} 00000 n \n".encode())
    pdf.extend(f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode()); return bytes(pdf)


@app.get("/api/reports/export.pdf")
@auth_required()
def export_pdf():
    mttd,mttr=metrics(); conn=db_conn(); rows=conn.execute("SELECT * FROM incidents ORDER BY timestamp DESC LIMIT 25").fetchall(); count=conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]; conn.close(); lines=["AI-Assisted Cybersecurity Incident Response Report",f"Generated: {iso_now()}",f"Incidents: {count} | MTTD: {mttd} min | MTTR: {mttr} min","","ID | Type | Severity | Status | Recommendation"]
    lines += [f"{x['external_id']} | {x['type']} | {x['severity']} | {x['status']} | {x['recommendation']}" for x in rows]
    return send_file(io.BytesIO(make_pdf(lines)),mimetype="application/pdf",as_attachment=True,download_name="incident_report.pdf")


@app.get("/api/audit")
@auth_required("Admin")
def audit_list():
    conn=db_conn(); rows=conn.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100").fetchall(); conn.close(); return jsonify([dict(x) for x in rows])


@app.get("/api/settings")
@auth_required("Admin")
def get_settings():
    conn=db_conn(); rows=conn.execute("SELECT key,value FROM settings").fetchall(); conn.close(); return jsonify({x["key"]:x["value"] for x in rows})


@app.patch("/api/settings")
@auth_required("Admin")
def update_settings():
    data=request.get_json() or {}; conn=db_conn()
    for key,value in data.items():
        if key in {"ai_sensitivity","platform_name"}: conn.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(key,str(value)))
    conn.commit(); conn.close(); audit(request.user["username"],"UPDATE_SETTINGS","settings",json.dumps(data)); return get_settings()


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=os.getenv("FLASK_DEBUG", "0") == "1")
