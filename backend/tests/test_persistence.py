from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from sqlalchemy import select

from app.core.config import get_settings
from app.db.models import AlertRule, ChangeCandidate, ChangeEvent, Notification, Scan, Target
from app.scanner.types import Service, Snapshot
from app.services.notifications import dispatch_notifications
from app.services.scans import enqueue, finish_scan
from app.worker import schedule_due


def make_target(db):
    target = Target(
        owner_id=1,
        name="lab",
        host="127.0.0.1",
        profile_id=1,
        authorized=True,
        enabled=True,
        interval_seconds=300,
        next_scan_at=datetime.now(UTC) + timedelta(hours=1),
    )
    db.add(target)
    db.commit()
    return target


def run(db, target, state="SUCCESS", open_port=True, certificates=None):
    job = enqueue(db, target, [8000])
    db.commit()
    assert job is not None
    job.state = "RUNNING"
    job.started_at = datetime.now(UTC)
    db.commit()
    snapshot = Snapshot(
        state=state,
        addresses=[target.host],
        ports=[8000],
        services=[Service(address=target.host, port=8000, state="open" if open_port else "closed")],
        certificates=certificates or [],
    )
    emitted = finish_scan(db, job.id, snapshot, get_settings())
    return job, emitted


def test_full_confirmation_sequence_and_failure_retains_baseline(session_factory):
    with session_factory() as db:
        t = make_target(db)
        a, events = run(db, t)
        assert [e.type for e in events] == ["INITIAL_BASELINE"]
        assert not run(db, t)[1]
        baseline = t.baseline_scan_id
        closed, events = run(db, t, open_port=False)
        assert not events and t.baseline_scan_id == baseline
        assert db.scalar(select(ChangeCandidate)).observations == 1
        assert [e.type for e in run(db, t, open_port=False)[1]] == ["REMOVED_PORT"]
        trusted = t.baseline_scan_id
        assert [e.type for e in run(db, t, "FAILED")[1]] == ["SCAN_FAILED"]
        assert t.baseline_scan_id == trusted
        assert [e.type for e in run(db, t)[1]] == ["NEW_PORT"]
        assert len(db.scalars(select(Scan)).all()) == 6


def test_partial_does_not_promote_and_repeated_failure_no_spam(session_factory):
    with session_factory() as db:
        t = make_target(db)
        run(db, t)
        old = t.baseline_scan_id
        assert [e.type for e in run(db, t, "PARTIAL", False)[1]] == ["SCAN_PARTIAL"]
        assert t.baseline_scan_id == old
        assert run(db, t, "PARTIAL", False)[1] == []
        assert not db.scalars(select(ChangeEvent).where(ChangeEvent.type == "REMOVED_PORT")).all()


def test_interruption_resets_candidate(session_factory):
    with session_factory() as db:
        t = make_target(db)
        run(db, t)
        run(db, t, open_port=False)
        run(db, t, "FAILED")
        assert not run(db, t, open_port=False)[1]
        assert [e.type for e in run(db, t, open_port=False)[1]] == ["REMOVED_PORT"]


def test_schedule_no_overlap_and_disabled_target(session_factory):
    with session_factory() as db:
        t = make_target(db)
        t.next_scan_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        schedule_due(db)
        schedule_due(db)
        assert len(db.scalars(select(Scan)).all()) == 1
        assert enqueue(db, t, [8000]) is None
        t.enabled = False
        t.next_scan_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        schedule_due(db)
        assert len(db.scalars(select(Scan)).all()) == 1


def test_notification_retry_does_not_invalidate_scan(session_factory):
    with session_factory() as db:
        t = make_target(db)
        rule = AlertRule(
            owner_id=1, channel="smtp", destination="lab@example.com", min_severity="INFO"
        )
        db.add(rule)
        db.commit()
        job, _ = run(db, t)
        with patch(
            "app.services.notifications.send_notification", side_effect=RuntimeError("secret-token")
        ):
            dispatch_notifications(db, get_settings())
        note = db.scalar(select(Notification))
        assert note.state == "PENDING" and note.attempts == 1 and "secret-token" not in note.error
        assert job.state == "SUCCESS"
        note.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        with patch("app.services.notifications.send_notification") as send:
            dispatch_notifications(db, get_settings())
            send.assert_called_once()
        assert note.state == "SENT"


def test_snapshot_immutable(session_factory):
    import pytest

    with session_factory() as db:
        t = make_target(db)
        job, _ = run(db, t)
        with pytest.raises(ValueError):
            finish_scan(db, job.id, Snapshot(state="FAILED"), get_settings())
