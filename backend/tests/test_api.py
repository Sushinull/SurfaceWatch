from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.db.models import AuthSession
from app.scanner.types import Snapshot
from app.worker import tick


def add_target(client, **kwargs):
    data = dict(
        name="Local lab", host="127.0.0.1", profile_id=1, authorized=True, interval_seconds=3600
    )
    data.update(kwargs)
    return client.post("/api/targets", json=data)


def test_auth_csrf_and_logout(client):
    assert client.get("/api/targets").status_code == 401
    assert (
        client.post("/api/auth/login", json={"username": "admin", "password": "wrong"}).status_code
        == 401
    )
    client.headers["Origin"] = "https://evil.example"
    assert (
        client.post(
            "/api/auth/login", json={"username": "admin", "password": "a-secure-test-password"}
        ).status_code
        == 403
    )
    del client.headers["Origin"]
    assert (
        client.post(
            "/api/auth/login", json={"username": "admin", "password": "a-secure-test-password"}
        ).status_code
        == 200
    )
    assert "HttpOnly" in client.get("/api/auth/me").request.headers.get(
        "cookie", ""
    ) or client.cookies.get("sw_session")
    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/auth/me").status_code == 401


def test_missing_csrf_header(client):
    del client.headers["X-SurfaceWatch"]
    assert (
        client.post("/api/auth/login", json={"username": "admin", "password": "x"}).status_code
        == 403
    )


def test_login_throttle(client):
    for _ in range(5):
        assert (
            client.post("/api/auth/login", json={"username": "admin", "password": "x"}).status_code
            == 401
        )
    assert (
        client.post("/api/auth/login", json={"username": "admin", "password": "x"}).status_code
        == 429
    )


def test_crud_queue_and_ownership(logged_in, session_factory):
    c = logged_in
    assert add_target(c, authorized=False).status_code == 422
    assert add_target(c, host="example.com;id").status_code == 422
    target = add_target(c).json()
    assert target["id"]
    assert add_target(c).status_code == 409
    scan = c.post(f"/api/targets/{target['id']}/scans")
    assert scan.status_code == 202
    assert c.post(f"/api/targets/{target['id']}/scans").status_code == 409
    assert c.delete(f"/api/targets/{target['id']}").status_code == 409
    assert c.get("/api/scans").json()[0]["state"] == "PENDING"
    assert c.post("/api/auth/logout").status_code == 204
    c.post("/api/auth/login", json={"username": "other", "password": "another-test-password"})
    assert c.get(f"/api/targets/{target['id']}").status_code == 404
    assert c.get(f"/api/scans/{scan.json()['id']}").status_code == 404
    assert c.get("/api/events").json() == []


def test_worker_and_baseline_api(logged_in, session_factory):
    from app.core.config import get_settings

    c = logged_in
    target = add_target(c).json()
    c.post(f"/api/targets/{target['id']}/scans")

    def scanner(host, ports, settings):
        from app.scanner.types import Service

        return Snapshot(
            state="SUCCESS",
            addresses=[host],
            ports=ports,
            services=[Service(address=host, port=p, state="closed") for p in ports],
        )

    tick(session_factory, get_settings(), scanner)
    assert c.get("/api/events").json()[0]["type"] == "INITIAL_BASELINE"
    assert c.get(f"/api/targets/{target['id']}").json()["baseline_scan_id"]
    assert c.get("/api/dashboard").json()["healthy_targets"] == 1
    assert c.get("/api/scans").json()[0]["state"] == "SUCCESS"
    assert c.delete(f"/api/targets/{target['id']}").status_code == 204
    assert c.get("/api/targets").json() == []
    assert len(c.get("/api/targets?archived=true").json()) == 1
    assert c.get("/api/scans").json()[0]["state"] == "SUCCESS"


def test_notifications_and_profile_validation(logged_in):
    c = logged_in
    assert c.post("/api/profiles", json={"name": "Bad", "ports": [0]}).status_code == 422
    p = c.post("/api/profiles", json={"name": "Lab", "ports": [8000, 8000, 443]}).json()
    assert p["ports"] == [443, 8000]
    assert c.post("/api/profiles", json={"name": "Lab", "ports": [80]}).status_code == 409
    assert (
        c.post(
            "/api/notifications/rules", json={"channel": "smtp", "destination": "bad"}
        ).status_code
        == 422
    )
    r = c.post(
        "/api/notifications/rules", json={"channel": "smtp", "destination": "lab@example.com"}
    ).json()
    assert c.post(f"/api/notifications/rules/{r['id']}/test").status_code == 202
    assert c.get("/api/notifications").json()[0]["state"] == "PENDING"
    assert "smtp_password" not in c.get("/api/notifications/config").text


def test_expired_session(logged_in, session_factory):
    with session_factory() as db:
        for s in db.scalars(select(AuthSession)):
            s.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    assert logged_in.get("/api/auth/me").status_code == 401


def test_events_filter_pagination_acknowledgment_and_ownership(logged_in, session_factory):
    from app.core.config import get_settings

    c = logged_in
    target = add_target(c).json()
    c.post(f"/api/targets/{target['id']}/scans")
    tick(
        session_factory,
        get_settings(),
        lambda *args: Snapshot(state="FAILED", errors=["controlled"]),
    )
    event = c.get(
        f"/api/events?target_id={target['id']}&severity=MEDIUM&event_type=SCAN_FAILED"
    ).json()[0]
    assert c.get("/api/events?severity=HIGH").json() == []
    assert c.get("/api/events?limit=1&offset=1").json() == []
    assert c.get("/api/events?since=2099-01-01T00:00:00Z").json() == []
    assert c.post(f"/api/events/{event['id']}/acknowledge").json()["acknowledged"] is True
    c.post("/api/auth/logout")
    c.post("/api/auth/login", json={"username": "other", "password": "another-test-password"})
    assert c.post(f"/api/events/{event['id']}/acknowledge").status_code == 404
    assert c.get("/api/events").json() == []
