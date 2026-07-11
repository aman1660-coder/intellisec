from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app


def test_auth_health_jwt_and_case_study_routes():
    client = TestClient(app)
    assert client.get("/api/health").status_code == 200

    email = f"test-{uuid4().hex[:8]}@example.com"
    registration = client.post(
        "/api/auth/register",
        json={"name": "Test User", "email": email, "password": "strong-password-123"},
    )
    assert registration.status_code == 200
    token = registration.json()["token"]

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["user"]["email"] == email

    login = client.post("/api/auth/login", json={"email": email, "password": "strong-password-123"})
    assert login.status_code == 200

    scans = client.get("/api/scans", headers={"Authorization": f"Bearer {token}"})
    assert scans.status_code == 200
    assert scans.json() == []

    case_study = client.get("/api/case-study")
    assert case_study.status_code == 200
    assert case_study.json()["scan_mode"] == "RESEARCH CASE STUDY"
