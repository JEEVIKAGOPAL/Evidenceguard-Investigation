from __future__ import annotations

import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from evidence_checker import analyze_evidence
from llm_service import explain_analysis
from wazuh import WazuhClient, WazuhError

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
DB_PATH = Path(os.getenv("DATABASE_PATH", str(BASE_DIR / "data" / "evidenceguard.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

APP_NAME = os.getenv("APP_NAME", "EvidenceGuard")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "ChangeThisPassword123!")
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"

app = FastAPI(title=f"{APP_NAME} API", version="1.0.0", description="Evidence-gap analysis for Wazuh security investigations")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
security = HTTPBearer(auto_error=False)
TOKENS: dict[str, dict[str, str]] = {}
wazuh_client = WazuhClient()

SAMPLE_ALERTS: list[dict[str, Any]] = [
    {
        "id": "DEMO-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": {"id": "001", "name": "ubuntu-agent"},
        "rule": {"id": "5710", "level": 10, "description": "Multiple SSH authentication failures"},
        "data": {"srcip": "192.0.2.45", "srcuser": "admin"},
        "full_log": "Illustrative demo alert: repeated SSH authentication failures detected.",
        "_demo": True,
    },
    {
        "id": "DEMO-002",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": {"id": "002", "name": "workstation-02"},
        "rule": {"id": "550", "level": 7, "description": "File integrity change detected"},
        "data": {"file": "/home/demo/important.txt", "user": "demo"},
        "full_log": "Illustrative demo alert: a monitored file was modified.",
        "_demo": True,
    },
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            alert_json TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            analysis_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        count = conn.execute("SELECT COUNT(*) AS n FROM incidents").fetchone()["n"]
        if count == 0 and DEMO_MODE:
            for alert in SAMPLE_ALERTS:
                incident_id = alert["id"]
                conn.execute(
                    "INSERT INTO incidents (id,title,severity,status,alert_json,evidence_json,analysis_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (incident_id, alert["rule"]["description"], severity_label(alert["rule"]["level"]), "Open", json.dumps(alert), json.dumps(default_evidence(alert)), None, utc_now(), utc_now()),
                )


def severity_label(level: Any) -> str:
    try:
        n = int(level)
    except (TypeError, ValueError):
        return "Medium"
    if n >= 12:
        return "Critical"
    if n >= 10:
        return "High"
    if n >= 7:
        return "Medium"
    return "Low"


def default_evidence(alert: dict[str, Any]) -> list[dict[str, str]]:
    rule_text = str(alert.get("rule", {}).get("description", "")).lower()
    auth_event = "ssh" in rule_text or "authentication" in rule_text or "login" in rule_text
    return [
        {"key": "source_ip", "label": "Source IP address", "status": "available" if alert.get("data", {}).get("srcip") else "unchecked", "source": "Wazuh alert", "notes": "Confirm the source address and its expected role."},
        {"key": "authentication_history", "label": "Authentication history", "status": "available" if auth_event else "unchecked", "source": "Authentication logs", "notes": "Review failures and any subsequent successful login." if auth_event else "Review relevant login activity for the incident window."},
        {"key": "user_activity", "label": "User activity after alert", "status": "unchecked", "source": "Audit/system logs", "notes": "Check commands, sessions, and related user actions."},
        {"key": "file_integrity", "label": "Related file integrity events", "status": "unchecked", "source": "Wazuh FIM", "notes": "Check whether files changed during the incident window."},
        {"key": "network_activity", "label": "Related network activity", "status": "unchecked", "source": "Firewall/network logs", "notes": "Correlate network connections with the affected endpoint."},
    ]


@app.on_event("startup")
def startup() -> None:
    init_db()


class LoginInput(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=180)
    severity: str = "Medium"
    alert: dict[str, Any]
    evidence: list[dict[str, Any]] | None = None


class EvidenceUpdate(BaseModel):
    evidence: list[dict[str, Any]]


class NotesInput(BaseModel):
    notes: str = Field(default="", max_length=5000)


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(security)) -> dict[str, str]:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Please sign in to continue.")
    user = TOKENS.get(credentials.credentials)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired. Please sign in again.")
    return user


def audit(username: str, action: str, details: str) -> None:
    with db() as conn:
        conn.execute("INSERT INTO audit_log (username,action,details,created_at) VALUES (?,?,?,?)", (username, action, details[:1000], utc_now()))


def row_to_incident(row: sqlite3.Row) -> dict[str, Any]:
    alert = json.loads(row["alert_json"])
    analysis = json.loads(row["analysis_json"]) if row["analysis_json"] else None
    return {
        "id": row["id"], "title": row["title"], "severity": row["severity"], "status": row["status"],
        "alert": alert, "evidence": json.loads(row["evidence_json"]), "analysis": analysis,
        "created_at": row["created_at"], "updated_at": row["updated_at"],
    }


@app.get("/", response_class=HTMLResponse)
def home() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "app": APP_NAME, "time": utc_now(), "demo_mode": DEMO_MODE}


@app.post("/api/login")
def login(payload: LoginInput) -> dict[str, Any]:
    # Prototype credentials are configured in .env; use a unique in-memory token per session.
    if not secrets.compare_digest(payload.username, ADMIN_USERNAME) or not secrets.compare_digest(payload.password, ADMIN_PASSWORD):
        raise HTTPException(status_code=401, detail="Incorrect username or password.")
    token = secrets.token_urlsafe(32)
    TOKENS[token] = {"username": payload.username, "role": "Administrator"}
    audit(payload.username, "login", "Successful sign-in")
    return {"access_token": token, "token_type": "bearer", "user": TOKENS[token]}


@app.post("/api/logout")
def logout(user: dict[str, str] = Depends(current_user), credentials: HTTPAuthorizationCredentials | None = Depends(security)) -> dict[str, str]:
    if credentials:
        TOKENS.pop(credentials.credentials, None)
    audit(user["username"], "logout", "Signed out")
    return {"message": "Signed out"}


@app.get("/api/dashboard")
def dashboard(user: dict[str, str] = Depends(current_user)) -> dict[str, Any]:
    with db() as conn:
        rows = conn.execute("SELECT severity,status FROM incidents").fetchall()
        recent = conn.execute("SELECT * FROM incidents ORDER BY updated_at DESC LIMIT 6").fetchall()
    counts = {key: 0 for key in ["Critical", "High", "Medium", "Low"]}
    for row in rows:
        counts[row["severity"] if row["severity"] in counts else "Medium"] += 1
    all_incidents = [row_to_incident(r) for r in recent]
    gaps = sum(sum(1 for e in item["evidence"] if e.get("status") == "missing") for item in all_incidents)
    return {"total_incidents": len(rows), "open_incidents": sum(1 for r in rows if r["status"] != "Resolved"), "severity": counts, "evidence_gaps": gaps, "recent": all_incidents, "user": user}


@app.get("/api/incidents")
def list_incidents(user: dict[str, str] = Depends(current_user)) -> dict[str, Any]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM incidents ORDER BY updated_at DESC").fetchall()
    return {"incidents": [row_to_incident(r) for r in rows]}


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str, user: dict[str, str] = Depends(current_user)) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    audit(user["username"], "view_incident", incident_id)
    return row_to_incident(row)


@app.post("/api/incidents")
def create_incident(payload: IncidentCreate, user: dict[str, str] = Depends(current_user)) -> dict[str, Any]:
    incident_id = "INC-" + secrets.token_hex(4).upper()
    evidence = payload.evidence if payload.evidence is not None else default_evidence(payload.alert)
    severity = payload.severity if payload.severity in {"Critical", "High", "Medium", "Low"} else "Medium"
    now = utc_now()
    with db() as conn:
        conn.execute("INSERT INTO incidents (id,title,severity,status,alert_json,evidence_json,analysis_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)", (incident_id, payload.title, severity, "Open", json.dumps(payload.alert), json.dumps(evidence), None, now, now))
    audit(user["username"], "create_incident", incident_id)
    return get_incident(incident_id, user)


@app.post("/api/incidents/{incident_id}/analyze")
def run_analysis(incident_id: str, user: dict[str, str] = Depends(current_user)) -> dict[str, Any]:
    incident = get_incident(incident_id, user)
    gap_result = analyze_evidence(incident["alert"], incident["evidence"])
    explanation = explain_analysis(incident["alert"], gap_result)
    result = {**gap_result, "llm": explanation, "analysis_time": utc_now()}
    with db() as conn:
        conn.execute("UPDATE incidents SET analysis_json=?,updated_at=? WHERE id=?", (json.dumps(result), utc_now(), incident_id))
    audit(user["username"], "analyze_incident", incident_id)
    return {"incident_id": incident_id, "analysis": result}


@app.put("/api/incidents/{incident_id}/evidence")
def update_evidence(incident_id: str, payload: EvidenceUpdate, user: dict[str, str] = Depends(current_user)) -> dict[str, Any]:
    allowed = {"available", "missing", "unchecked", "unavailable"}
    for item in payload.evidence:
        if item.get("status") not in allowed:
            raise HTTPException(status_code=422, detail="Evidence status must be available, missing, unchecked, or unavailable.")
        if not item.get("key") or not item.get("label"):
            raise HTTPException(status_code=422, detail="Each evidence item needs key and label.")
    with db() as conn:
        exists = conn.execute("SELECT id FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not exists:
            raise HTTPException(status_code=404, detail="Incident not found")
        conn.execute("UPDATE incidents SET evidence_json=?,analysis_json=NULL,updated_at=? WHERE id=?", (json.dumps(payload.evidence), utc_now(), incident_id))
    audit(user["username"], "update_evidence", incident_id)
    return get_incident(incident_id, user)


@app.post("/api/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: str, payload: NotesInput, user: dict[str, str] = Depends(current_user)) -> dict[str, Any]:
    with db() as conn:
        exists = conn.execute("SELECT id FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not exists:
            raise HTTPException(status_code=404, detail="Incident not found")
        conn.execute("UPDATE incidents SET status='Resolved',updated_at=? WHERE id=?", (utc_now(), incident_id))
    audit(user["username"], "mark_resolved", f"{incident_id}; analyst note: {payload.notes}")
    return get_incident(incident_id, user)


@app.get("/api/reports/{incident_id}")
def download_report(incident_id: str, user: dict[str, str] = Depends(current_user)) -> JSONResponse:
    incident = get_incident(incident_id, user)
    report = {"report_title": "EvidenceGuard Investigation Report", "generated_at": utc_now(), "analyst": user["username"], "incident": incident}
    audit(user["username"], "download_report", incident_id)
    return JSONResponse(content=report, headers={"Content-Disposition": f'attachment; filename="EvidenceGuard-{incident_id}.json"'})


@app.get("/api/audit")
def audit_records(user: dict[str, str] = Depends(current_user)) -> dict[str, Any]:
    with db() as conn:
        rows = conn.execute("SELECT username,action,details,created_at FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()
    return {"records": [dict(r) for r in rows]}


@app.get("/api/wazuh/agents")
def wazuh_agents(user: dict[str, str] = Depends(current_user)) -> dict[str, Any]:
    try:
        agents = wazuh_client.get_agents()
        return {"agents": agents, "source": "wazuh_api", "demo_mode": False}
    except WazuhError as exc:
        # Do not disguise integration failure as live data.
        raise HTTPException(status_code=502, detail=f"Wazuh agent request failed: {exc}") from exc


@app.get("/api/wazuh/alerts")
def wazuh_alerts(user: dict[str, str] = Depends(current_user)) -> dict[str, Any]:
    alerts_file = os.getenv("WAZUH_ALERTS_FILE", "").strip()
    if alerts_file:
        path = Path(alerts_file)
        if not path.exists():
            raise HTTPException(status_code=502, detail="WAZUH_ALERTS_FILE is configured but the file cannot be found.")
        alerts: list[dict[str, Any]] = []
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return {"alerts": alerts[-100:], "source": "alerts_file", "demo_mode": False}
        except OSError as exc:
            raise HTTPException(status_code=502, detail=f"Could not read configured alerts file: {exc}") from exc
    if DEMO_MODE:
        return {"alerts": SAMPLE_ALERTS, "source": "illustrative_demo_data", "demo_mode": True, "notice": "These are sample alerts, not live Wazuh events. Configure WAZUH_ALERTS_FILE to use an accessible alerts.json file."}
    raise HTTPException(status_code=503, detail="No alerts source configured. Set WAZUH_ALERTS_FILE to an accessible Wazuh alerts.json file.")


def default_evidence(alert: dict[str, Any]) -> list[dict[str, str]]:
    rule = alert.get("rule", {}) if isinstance(alert.get("rule"), dict) else {}
    description = str(rule.get("description", "")).lower()
    is_auth = any(word in description for word in ("ssh", "login", "authentication", "auth"))
    data = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}
    return [
        {"key": "source_ip", "label": "Source IP address", "status": "available" if data.get("srcip") else "unchecked", "source": "Wazuh alert", "notes": "Confirm whether the address is expected for this endpoint."},
        {"key": "authentication_history", "label": "Authentication history", "status": "unchecked", "source": "Authentication logs", "notes": "Check failed and successful authentication events in the relevant time window."},
        {"key": "user_activity", "label": "User activity", "status": "unchecked", "source": "System audit logs", "notes": "Review related sessions and activity by the affected account."},
        {"key": "file_integrity", "label": "Related file integrity events", "status": "unchecked", "source": "Wazuh FIM", "notes": "Check whether relevant files changed around the event time."},
        {"key": "network_activity", "label": "Related network activity", "status": "unchecked", "source": "Firewall/network logs", "notes": "Correlate endpoint connections with the event time window."},
    ]
