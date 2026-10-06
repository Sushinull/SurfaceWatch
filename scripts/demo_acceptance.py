"""Destructive acceptance checks ONLY for a fresh, disposable Compose project.

Requires COMPOSE_PROJECT_NAME=surfacewatch-regression and --disposable. Never
run against an operator's installation. The caller owns volume cleanup.
"""

import argparse
import http.cookiejar
import json
import os
import secrets
import subprocess
import time
import urllib.request
from pathlib import Path

COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.demo.yml"]
BASE = "http://localhost:8080"


def compose(*args, env=None, stdin=None):
    return subprocess.run(
        [*COMPOSE, *args],
        env=env,
        input=stdin,
        text=True,
        capture_output=True,
        check=True,
        timeout=180,
    ).stdout


def wait_for(read, accept, description, timeout=240, interval=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = read()
        if accept(value):
            return value
        time.sleep(interval)
    raise AssertionError(f"Timed out: {description}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable", action="store_true", required=True)
    parser.add_argument("--credentials-file", type=Path)
    args = parser.parse_args()
    if os.environ.get("COMPOSE_PROJECT_NAME") != "surfacewatch-regression":
        parser.error("Use only COMPOSE_PROJECT_NAME=surfacewatch-regression with a fresh database")
    effective = json.loads(compose("config", "--format", "json"))
    services = effective["services"]
    assert effective["networks"]["lab"]["internal"]
    assert set(services["lab"]["networks"]) == {"lab"} and not services["lab"].get("ports")
    assert {"lab", "default"} <= set(services["mailpit"]["networks"])
    for port in services["mailpit"]["ports"]:
        assert port["host_ip"] == "127.0.0.1" and int(port["target"]) == 8025
    assert not services["worker"].get("ports") and not services["backend"].get("ports")
    assert "127.0.0.1:8025" in compose("port", "mailpit", "8025")
    with urllib.request.urlopen("http://localhost:8025/", timeout=10) as response:
        assert response.status == 200
    print("PASS Mailpit actual published port + loopback HTTP; lab remains internal", flush=True)

    password = secrets.token_urlsafe(24)
    username = "acceptance-admin"
    # Create a fresh test user without putting credentials into CLI arguments/logs.
    compose(
        "exec",
        "-T",
        "backend",
        "python",
        "-c",
        "import json,sys; from app.core.auth import password_hasher; "
        "from app.db.models import User; from app.db.session import SessionLocal; "
        "data=json.load(sys.stdin); db=SessionLocal(); "
        "db.add(User(username=data['username'],password_hash=password_hasher.hash(data['password']))); "
        "db.commit(); db.close()",
        stdin=json.dumps({"username": username, "password": password}),
    )
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def api(path, method="GET", body=None):
        req = urllib.request.Request(
            BASE + "/api" + path,
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json", "X-SurfaceWatch": "1", "Origin": BASE},
        )
        with opener.open(req, timeout=20) as response:
            return json.load(response) if response.status != 204 else None

    api("/auth/login", "POST", {"username": username, "password": password})
    config = api("/notifications/config")
    assert config == {"smtp": True, "telegram": False, "discord": False}
    profile = api("/profiles", "POST", {"name": "Acceptance demo", "ports": [8000, 8081, 8443]})
    target = api(
        "/targets",
        "POST",
        {
            "name": "Acceptance lab",
            "host": "172.30.0.10",
            "profile_id": profile["id"],
            "authorized": True,
            "interval_seconds": 3600,
        },
    )
    target_id = target["id"]

    def detail():
        return api(f"/targets/{target_id}")

    def events():
        return api(f"/events?target_id={target_id}&limit=200")

    def scan():
        job = api(f"/targets/{target_id}/scans", "POST")
        result = wait_for(
            lambda: api(f"/scans/{job['id']}"),
            lambda s: s["state"] not in {"PENDING", "RUNNING"},
            "complete scan",
        )
        assert result["state"] == "SUCCESS", result.get("error")
        return result, [e for e in events() if e["scan_id"] == job["id"]]

    def recreate_lab(**changes):
        compose("up", "-d", "--force-recreate", "lab", env={**os.environ, **changes})
        time.sleep(2)

    baseline, emitted = scan()
    assert any(e["type"] == "INITIAL_BASELINE" for e in emitted)
    assert {s["port"] for s in detail()["services"]} == {8000, 8443}
    assert not scan()[1]
    print("PASS baseline + equivalent scan with no duplicate event", flush=True)
    recreate_lab(EXTRA_SERVICE="true")
    _, emitted = scan()
    assert any(e["type"] == "NEW_PORT" and e["details"]["port"] == 8081 for e in emitted)
    before_closure = detail()["baseline_scan_id"]
    recreate_lab(EXTRA_SERVICE="false")
    _, emitted = scan()
    assert not any(e["type"] == "REMOVED_PORT" for e in emitted)
    assert detail()["baseline_scan_id"] == before_closure
    assert detail()["status"] == "Confirming closure"
    _, emitted = scan()
    assert any(e["type"] == "REMOVED_PORT" and e["details"]["port"] == 8081 for e in emitted)
    assert any(e["type"] in {"TLS_RENEWED", "TLS_CHANGED"} for e in events())
    print("PASS NEW_PORT + two-success closure confirmation + certificate change", flush=True)
    recreate_lab(CERT_DAYS="6")
    _, emitted = scan()
    assert any(e["type"] == "TLS_CRITICAL" and e["severity"] == "HIGH" for e in emitted)
    print("PASS six-day TLS certificate yields TLS_CRITICAL/HIGH", flush=True)

    trusted = detail()["baseline_scan_id"]
    job = api(f"/targets/{target_id}/scans", "POST")
    wait_for(
        lambda: api(f"/scans/{job['id']}"), lambda s: s["state"] == "RUNNING", "worker RUNNING"
    )
    compose("kill", "-s", "SIGKILL", "worker")
    compose("up", "-d", "worker")
    failed = wait_for(
        lambda: api(f"/scans/{job['id']}"), lambda s: s["state"] == "FAILED", "recovery"
    )
    assert "Worker interrupted" in failed["error"]
    assert detail()["baseline_scan_id"] == trusted
    recovered_events = [e for e in events() if e["scan_id"] == job["id"]]
    assert [e["type"] for e in recovered_events] == ["SCAN_FAILED"]
    print(
        "PASS real SIGKILL/restart -> FAILED + SCAN_FAILED; baseline intact; no fake removal",
        flush=True,
    )

    rule = api(
        "/notifications/rules",
        "POST",
        {
            "channel": "smtp",
            "destination": "demo@example.test",
            "min_severity": "LOW",
        },
    )
    note = api(f"/notifications/rules/{rule['id']}/test", "POST")
    wait_for(
        lambda: api("/notifications"),
        lambda ns: any(n["id"] == note["id"] and n["state"] == "SENT" for n in ns),
        "SMTP SENT",
    )

    def messages():
        with urllib.request.urlopen(
            "http://localhost:8025/api/v1/messages", timeout=10
        ) as response:
            return json.load(response)["messages"]

    received = wait_for(messages, lambda ms: len(ms) > 0, "Mailpit received message")
    message = next(m for m in received if m["Subject"] == "SurfaceWatch change alert")
    assert message["From"]["Address"] == "surfacewatch@localhost"
    assert any(t["Address"] == "demo@example.test" for t in message["To"])
    with urllib.request.urlopen(
        f"http://localhost:8025/api/v1/message/{message['ID']}", timeout=10
    ) as response:
        assert "SurfaceWatch test notification" in json.load(response)["Text"]
    print(
        "PASS API SMTP CONFIGURED + outbox SENT + real Mailpit sender/recipient/subject/body",
        flush=True,
    )

    # Advance only this disposable target's clock; production minimum interval stays 300s.
    compose(
        "exec",
        "-T",
        "backend",
        "python",
        "-c",
        "from datetime import UTC,datetime; from app.db.models import Target; "
        "from app.db.session import SessionLocal; db=SessionLocal(); "
        f"t=db.get(Target,{target_id}); t.next_scan_at=datetime.now(UTC); db.commit(); db.close()",
    )
    scheduled = wait_for(
        lambda: api(f"/scans?target_id={target_id}"),
        lambda ss: any(s["source"] == "scheduled" and s["state"] == "SUCCESS" for s in ss),
        "scheduled SUCCESS",
    )
    assert sum(s["state"] in {"PENDING", "RUNNING"} for s in scheduled) <= 1
    print("PASS persisted due timestamp -> scheduled SUCCESS without overlap", flush=True)
    assert sum(e["type"] == "TLS_CRITICAL" for e in events()) == 1
    print(
        "PASS unchanged TLS warning remains deduplicated across interrupted scan recovery",
        flush=True,
    )

    # Idle SIGTERM, then a durable PENDING job while the worker is stopped.
    compose("stop", "--timeout", "30", "worker")
    pending = api(f"/targets/{target_id}/scans", "POST")
    assert api(f"/scans/{pending['id']}")["state"] == "PENDING"
    compose("up", "-d", "worker")
    wait_for(
        lambda: api(f"/scans/{pending['id']}"),
        lambda s: s["state"] == "SUCCESS",
        "durable PENDING restart",
    )
    print("PASS idle SIGTERM + durable PENDING job completes after worker restart", flush=True)

    # A database interruption must retain data; never reset or remove the volume.
    trusted = detail()["baseline_scan_id"]
    compose("stop", "--timeout", "10", "db")
    time.sleep(5)
    compose("up", "-d", "--wait", "db", "backend", "worker")
    assert detail()["baseline_scan_id"] == trusted
    print(
        "PASS real database stop/start preserves trusted baseline and restores API/worker",
        flush=True,
    )

    # The worker consumes PostgreSQL jobs directly, even while the API is stopped.
    independent = api(f"/targets/{target_id}/scans", "POST")
    compose("stop", "--timeout", "10", "backend")

    def worker_job_state():
        return compose(
            "exec",
            "-T",
            "worker",
            "python",
            "-c",
            "from app.db.session import SessionLocal; from app.db.models import Scan; "
            f"db=SessionLocal(); print(db.get(Scan,{independent['id']}).state); db.close()",
        ).strip()

    wait_for(worker_job_state, lambda state: state == "SUCCESS", "worker independent of API")
    compose("up", "-d", "--wait", "backend")
    assert api(f"/scans/{independent['id']}")["state"] == "SUCCESS"
    assert (
        sum(s["state"] in {"PENDING", "RUNNING"} for s in api(f"/scans?target_id={target_id}")) == 0
    )
    assert sum(e["type"] == "TLS_CRITICAL" for e in events()) == 1
    print(
        "PASS worker finishes while API stopped; restart retains immutable history without duplicates",
        flush=True,
    )
    if args.credentials_file:
        args.credentials_file.write_text(json.dumps({"username": username, "password": password}))
        args.credentials_file.chmod(0o600)
    print(
        "PASS Docker demo acceptance: original scenarios plus dedupe, SIGTERM/PENDING, database restart, API outage",
        flush=True,
    )


if __name__ == "__main__":
    main()
