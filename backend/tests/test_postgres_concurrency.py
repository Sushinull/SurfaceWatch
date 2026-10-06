"""Real PostgreSQL locks/constraints; deliberately not simulated with SQLite."""

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, event, select, text
from sqlalchemy.exc import IntegrityError

from app.core.config import get_settings
from app.db.models import AlertRule, ChangeEvent, Notification, Scan, Target
from app.services.scans import enqueue, finish_scan
from app.worker import schedule_due
from tests.test_api import add_target
from tests.test_diff import snapshot
from tests.test_persistence import make_target

pytestmark = pytest.mark.skipif(not os.getenv("TEST_DATABASE_URL"), reason="requires PostgreSQL")


def race(*operations):
    barrier = threading.Barrier(len(operations))

    def invoke(operation):
        barrier.wait(timeout=10)
        return operation()

    with ThreadPoolExecutor(max_workers=len(operations)) as executor:
        futures = [executor.submit(invoke, operation) for operation in operations]
        return [future.result(timeout=20) for future in futures]


def test_two_manual_enqueues_have_one_active_job(session_factory):
    with session_factory() as db:
        target_id = make_target(db).id

    def queue():
        with session_factory() as db:
            target = db.get(Target, target_id)
            job = enqueue(db, target, [22])
            db.commit()
            return job.id if job else None

    assert sum(result is not None for result in race(queue, queue)) == 1
    with session_factory() as db:
        assert len(db.scalars(select(Scan)).all()) == 1


@pytest.mark.parametrize("manual", [False, True])
def test_scheduler_overlap_with_scheduler_or_manual(session_factory, manual):
    with session_factory() as db:
        target = make_target(db)
        target.next_scan_at = datetime.now(UTC) - timedelta(hours=1)
        db.commit()
        target_id = target.id

    def scheduled():
        with session_factory() as db:
            schedule_due(db)

    def requested():
        with session_factory() as db:
            target = db.scalar(select(Target).where(Target.id == target_id).with_for_update())
            enqueue(db, target, [22])
            db.commit()

    race(scheduled, requested if manual else scheduled)
    with session_factory() as db:
        assert len(db.scalars(select(Scan)).all()) == 1


def test_concurrent_finish_refreshes_state_and_emits_once(session_factory):
    with session_factory() as db:
        target = make_target(db)
        job = enqueue(db, target, [22, 80])
        job.state = "RUNNING"
        job.started_at = datetime.now(UTC)
        db.commit()
        scan_id = job.id
    barrier = threading.Barrier(2)

    def complete():
        with session_factory() as db:
            cached = db.get(Scan, scan_id)
            assert cached.state == "RUNNING"
            barrier.wait(timeout=10)
            try:
                finish_scan(db, scan_id, snapshot(), get_settings())
                return "committed"
            except ValueError:
                db.rollback()
                return "rejected"

    assert sorted(race(complete, complete)) == ["committed", "rejected"]
    with session_factory() as db:
        assert len(db.scalars(select(ChangeEvent)).all()) == 1
        assert db.get(Scan, scan_id).state == "SUCCESS"


@pytest.mark.parametrize("archive", [False, True])
def test_api_edit_or_archive_racing_manual_queue(logged_in, session_factory, archive):
    c = logged_in
    target = add_target(c).json()
    path = f"/api/targets/{target['id']}"

    def change():
        if archive:
            return c.delete(path).status_code
        return c.put(
            path,
            json=dict(
                name="Edited", host="127.0.0.1", profile_id=1, authorized=True, interval_seconds=600
            ),
        ).status_code

    changed, queued = race(change, lambda: c.post(path + "/scans").status_code)
    assert (changed, queued) in ({(204, 404), (409, 202)} if archive else {(200, 202), (409, 202)})
    with session_factory() as db:
        scans = db.scalars(select(Scan)).all()
        assert len(scans) == (0 if changed == 204 else 1)
        assert not (db.get(Target, target["id"]).archived and scans)


def test_api_duplicate_target_creation_is_controlled(logged_in):
    results = race(
        lambda: add_target(logged_in).status_code, lambda: add_target(logged_in).status_code
    )
    assert sorted(results) == [201, 409]


def test_foreign_keys_protect_outbox_rule(session_factory):
    with session_factory() as db:
        rule = AlertRule(owner_id=1, channel="smtp", destination="lab@example.test")
        db.add(rule)
        db.flush()
        db.add(Notification(rule_id=rule.id, payload="test"))
        db.commit()
        with pytest.raises(IntegrityError):
            db.execute(delete(AlertRule).where(AlertRule.id == rule.id))
            db.commit()
        db.rollback()
        assert db.scalar(select(Notification.rule_id)) == rule.id


def test_concurrent_rule_creation_respects_owner_cap(logged_in, session_factory):
    c = logged_in
    data = {"channel": "smtp", "destination": "lab@example.test"}
    for _ in range(9):
        assert c.post("/api/notifications/rules", json=data).status_code == 201

    def pause(conn, cursor, statement, parameters, context, executemany):
        if "FROM alert_rules" in statement and "SELECT" in statement:
            time.sleep(0.2)  # Widen the real count/insert window; not a fake count.

    bind = session_factory.kw["bind"]
    event.listen(bind, "after_cursor_execute", pause)
    try:
        statuses = race(
            lambda: c.post("/api/notifications/rules", json=data).status_code,
            lambda: c.post("/api/notifications/rules", json=data).status_code,
        )
    finally:
        event.remove(bind, "after_cursor_execute", pause)
    assert sorted(statuses) == [201, 409]
    assert len(c.get("/api/notifications/rules").json()) == 10


def test_advisory_lock_excludes_second_worker(session_factory):
    with (
        session_factory.kw["bind"].connect() as first,
        session_factory.kw["bind"].connect() as second,
    ):
        assert first.scalar(text("SELECT pg_try_advisory_lock(74193621)"))
        first.commit()
        try:
            assert not second.scalar(text("SELECT pg_try_advisory_lock(74193621)"))
            second.commit()
        finally:
            assert first.scalar(text("SELECT pg_advisory_unlock(74193621)"))
            first.commit()
