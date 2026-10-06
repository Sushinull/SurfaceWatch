"""Regressions reproduced against the immutable v1.0.0 source tree."""

import io
import logging
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from app.api.targets import target_view
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.db.models import ChangeEvent, Notification, Scan
from app.scanner.types import Snapshot
from app.services.scans import enqueue, finish_scan
from app.worker import tick
from tests.test_diff import cert, snapshot
from tests.test_persistence import make_target, run


def test_stale_session_cannot_overwrite_completed_snapshot(session_factory):
    with session_factory() as original, session_factory() as recovery:
        target = make_target(original)
        job = enqueue(original, target, [8000])
        job.state = "RUNNING"
        job.started_at = datetime.now(UTC)
        original.commit()
        finish_scan(recovery, job.id, Snapshot(state="FAILED"), get_settings())
        with pytest.raises(ValueError, match="immutable"):
            finish_scan(original, job.id, snapshot(), get_settings())
        original.rollback()
        original.refresh(job)
        original.refresh(target)
        assert job.state == "FAILED" and target.baseline_scan_id is None
        assert len(original.scalars(select(ChangeEvent)).all()) == 1


def test_completion_database_failure_is_recovered_on_next_tick(session_factory, monkeypatch):
    with session_factory() as db:
        target = make_target(db)
        baseline, _ = run(db, target)
        job = enqueue(db, target, [8000])
        db.commit()
        job_id, target_id, baseline_id = job.id, target.id, baseline.id
    with monkeypatch.context() as patcher:
        patcher.setattr(
            "app.worker.finish_scan",
            lambda *_: (_ for _ in ()).throw(OperationalError("commit", {}, Exception())),
        )
        with pytest.raises(OperationalError):
            tick(session_factory, get_settings(), lambda *_: snapshot())
    tick(session_factory, get_settings(), lambda *_: snapshot())
    with session_factory() as db:
        assert db.get(Scan, job_id).state == "FAILED"
        assert db.get(type(target), target_id).baseline_scan_id == baseline_id
        assert [e.type for e in db.scalars(select(ChangeEvent).order_by(ChangeEvent.id))] == [
            "INITIAL_BASELINE",
            "SCAN_FAILED",
        ]
        enqueue(db, db.get(type(target), target_id), [8000])
        db.commit()
    tick(session_factory, get_settings(), lambda *_: snapshot(ports=(8000,), states=("open",)))
    with session_factory() as db:
        assert db.scalar(select(Scan.state).order_by(Scan.id.desc()).limit(1)) == "SUCCESS"


@pytest.mark.parametrize("uncertain", ["FAILED", "PARTIAL"])
def test_uncertainty_does_not_rearm_same_tls_warning(session_factory, uncertain):
    from app.db.models import AlertRule

    with session_factory() as db:
        target = make_target(db)
        db.add(
            AlertRule(
                owner_id=1, channel="smtp", destination="lab@example.test", min_severity="LOW"
            )
        )
        db.commit()
        warning = cert(6)
        run(db, target, certificates=[warning])
        run(db, target, uncertain)
        events = run(db, target, certificates=[warning])[1]
        assert not any(e.type == "TLS_CRITICAL" for e in events)
        assert (
            len(db.scalars(select(ChangeEvent).where(ChangeEvent.type == "TLS_CRITICAL")).all())
            == 1
        )
        assert len(db.scalars(select(Notification)).all()) == 2  # TLS warning + uncertainty
        run(db, target, certificates=[cert(90)])
        assert [e.type for e in run(db, target, certificates=[cert(6, fingerprint="new")])[1]] == [
            "TLS_CHANGED",
            "TLS_CRITICAL",
        ]


def test_low_event_does_not_hide_unacknowledged_high_event(session_factory):
    with session_factory() as db:
        target = make_target(db)
        job, _ = run(db, target)
        high = ChangeEvent(
            target_id=target.id,
            scan_id=job.id,
            type="NEW_PORT",
            severity="HIGH",
            message="Database port",
            details={},
            fingerprint="high",
        )
        low = ChangeEvent(
            target_id=target.id,
            scan_id=job.id,
            type="DNS_CHANGED",
            severity="LOW",
            message="DNS changed",
            details={},
            fingerprint="low",
        )
        db.add_all([high, low])
        db.commit()
        assert target_view(db, target)["status"] == "Changes detected"
        high.acknowledged = True
        db.commit()
        assert target_view(db, target)["status"] == "Healthy"


def test_invalid_login_never_echoes_password(client):
    sentinel = "invalid-password-sentinel-" * 12
    response = client.post("/api/auth/login", json={"username": "admin", "password": sentinel})
    assert response.status_code == 422
    assert sentinel not in response.text
    assert all(set(error) <= {"type", "loc", "msg"} for error in response.json()["detail"])


def test_settings_errors_hide_secret_inputs():
    sentinel = "invalid-secret-sentinel"
    with pytest.raises(ValidationError) as captured:
        Settings(_env_file=None, secret_key=sentinel)
    assert sentinel not in str(captured.value)
    with pytest.raises(ValidationError) as model_error:
        Settings(
            _env_file=None,
            secret_key="valid-0123456789abcdef0123456789abcdef",
            smtp_password=sentinel,
            tls_critical_days=31,
        )
    assert sentinel not in str(model_error.value)


def test_uvicorn_errors_use_safe_json_logging(monkeypatch):
    stream = io.StringIO()
    root = logging.getLogger()
    uvicorn = logging.getLogger("uvicorn.error")
    previous = (root.handlers[:], root.level, uvicorn.handlers[:], uvicorn.propagate, uvicorn.level)
    handler = logging.StreamHandler(stream)
    uvicorn.handlers = [handler]
    uvicorn.propagate = False
    uvicorn.setLevel(logging.INFO)
    monkeypatch.setattr("sys.stderr", stream)
    try:
        configure_logging()
        try:
            raise RuntimeError("fake-provider-token-sentinel")
        except RuntimeError:
            uvicorn.error("Exception in ASGI application", exc_info=True)
        assert "fake-provider-token-sentinel" not in stream.getvalue()
        assert '"logger": "uvicorn.error"' in stream.getvalue()
    finally:
        root.handlers, root.level, uvicorn.handlers, uvicorn.propagate, uvicorn.level = previous


def test_whitespace_profile_name_rejected(logged_in):
    response = logged_in.post("/api/profiles", json={"name": " \t\n ", "ports": [443]})
    assert response.status_code == 422


@pytest.mark.parametrize("days,expected", [(10, "CRITICAL"), (45, "WARNING")])
def test_certificate_badge_uses_operator_thresholds(
    logged_in, session_factory, monkeypatch, days, expected
):
    settings = get_settings().model_copy(
        update={"tls_critical_days": 14, "tls_second_warning_days": 30, "tls_warning_days": 60}
    )
    monkeypatch.setattr("app.api.targets.get_settings", lambda: settings)
    with session_factory() as db:
        target = make_target(db)
        run(db, target, certificates=[cert(days)])
        target_id = target.id
    certificate = logged_in.get(f"/api/targets/{target_id}").json()["certificates"][0]
    assert certificate.get("status") == expected
