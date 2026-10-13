import os
import tempfile

os.environ["SQLITE_DB"] = os.path.join(tempfile.gettempdir(), "cyber_ir_test.db")
from app import app

client = app.test_client()

def login():
    r = client.post("/api/auth/login", json={"username":"analyst","password":"Analyst@123"})
    assert r.status_code == 200
    return r.get_json()["token"]

def test_health():
    assert client.get("/api/health").status_code == 200

def test_auth_and_dashboard():
    token = login()
    r = client.get("/api/dashboard", headers={"Authorization":f"Bearer {token}"})
    assert r.status_code == 200
    assert "active" in r.get_json()

def test_manual_event_creates_incident():
    token = login()
    r = client.post("/api/events", json={"source_ip":"185.44.91.22","failed_logins":95,"requests_per_minute":920,"bytes":850000,"port":22}, headers={"Authorization":f"Bearer {token}"})
    assert r.status_code == 201
    assert r.get_json()["suspicious"] is True


def test_ai_status_requires_auth():
    assert client.get("/api/ai/status").status_code == 401

def test_ai_status_does_not_expose_api_key():
    token = login()
    r = client.get("/api/ai/status", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    payload = r.get_json()
    assert "configured" in payload and "mode" in payload
    assert "api_key" not in payload and "OPENAI_API_KEY" not in payload
