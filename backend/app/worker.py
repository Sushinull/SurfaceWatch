import logging
import signal
import threading
from datetime import UTC, datetime

from sqlalchemy import select, text

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.models import Scan, ScanProfile, Target
from app.db.session import SessionLocal, engine
from app.scanner.pipeline import execute_scan
from app.scanner.types import ScanState, Snapshot
from app.services.notifications import dispatch_notifications
from app.services.scans import enqueue, finish_scan

log = logging.getLogger(__name__)
stop = threading.Event()


def schedule_due(db):
    targets = db.scalars(
        select(Target)
        .where(
            Target.enabled.is_(True),
            Target.archived.is_(False),
            Target.next_scan_at <= datetime.now(UTC),
        )
        .with_for_update(skip_locked=True)
    ).all()
    for target in targets:
        enqueue(db, target, db.get(ScanProfile, target.profile_id).ports, "scheduled")
    db.commit()


def tick(session_factory=SessionLocal, settings=None, scanner=execute_scan):
    settings = settings or get_settings()
    with session_factory() as db:
        schedule_due(db)
        scan = db.scalar(
            select(Scan)
            .where(Scan.state == "PENDING")
            .order_by(Scan.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if scan:
            scan.state = "RUNNING"
            scan.started_at = datetime.now(UTC)
            db.commit()
            log.info(
                "scan_started scan_id=%s target_id=%s host=%s",
                scan.id,
                scan.target_id,
                scan.target_host,
            )
            try:
                result = scanner(scan.target_host, scan.ports, settings)
            except Exception as exc:
                result = Snapshot(
                    state=ScanState.FAILED,
                    ports=scan.ports,
                    errors=[f"Scan pipeline error: {type(exc).__name__}"],
                )
            finish_scan(db, scan.id, result, settings)
        dispatch_notifications(db, settings)


def main():
    configure_logging()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    # Session-level advisory lock lives on a dedicated connection for the worker's
    # lifetime. One worker in V1; PostgreSQL uniqueness also protects API enqueue.
    with engine.connect() as lock:
        if engine.dialect.name == "postgresql":
            if not lock.execute(text("SELECT pg_try_advisory_lock(74193621)")).scalar():
                raise RuntimeError("Another SurfaceWatch worker is already active")
            lock.commit()
        with SessionLocal() as db:
            for scan in db.scalars(select(Scan).where(Scan.state == "RUNNING")).all():
                finish_scan(
                    db,
                    scan.id,
                    Snapshot(
                        state=ScanState.FAILED,
                        ports=scan.ports,
                        errors=["Worker interrupted; previous baseline retained"],
                    ),
                    get_settings(),
                )
        log.info("worker_ready")
        while not stop.is_set():
            if engine.dialect.name == "postgresql":
                # A lost dedicated connection means the advisory lock was lost. Exit
                # instead of running alongside a newly started worker after DB restart.
                lock.execute(text("SELECT 1"))
                lock.commit()
            try:
                tick()
            except Exception as exc:
                log.error("worker_tick_error type=%s", type(exc).__name__)
            stop.wait(get_settings().worker_poll_seconds)


if __name__ == "__main__":
    main()
