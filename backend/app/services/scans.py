import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from app.core.config import Settings
from app.db.models import (
    AlertRule,
    ChangeCandidate,
    ChangeEvent,
    DNSRecord,
    Notification,
    Scan,
    ScanService,
    Target,
    TLSCertificate,
)
from app.diff.engine import SEVERITIES, compare
from app.scanner.types import ScanState, Snapshot

log = logging.getLogger(__name__)


def utc(dt):
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def enqueue(db, target: Target, ports: list[int], source="manual") -> Scan | None:
    job = Scan(target_id=target.id, target_host=target.host, ports=ports, source=source)
    try:
        with db.begin_nested():
            db.add(job)
            db.flush()
        target.next_scan_at = datetime.now(UTC) + timedelta(seconds=target.interval_seconds)
        return job
    except IntegrityError:
        return None


def finish_scan(db, scan_id: int, snapshot: Snapshot, settings: Settings):
    target_id = db.scalar(select(Scan.target_id).where(Scan.id == scan_id))
    # Match API/scheduler lock order (target before scan). Refresh cached identities:
    # a late result must not overwrite a completion committed by recovery elsewhere.
    target = db.scalar(
        select(Target)
        .where(Target.id == target_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    scan = db.scalar(
        select(Scan)
        .where(Scan.id == scan_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if scan is None or scan.state != "RUNNING":
        raise ValueError("Only a running scan can be completed; snapshots are immutable")
    previous_scan = db.get(Scan, target.baseline_scan_id) if target.baseline_scan_id else None
    previous = Snapshot.model_validate(previous_scan.snapshot) if previous_scan else None
    scan.state = snapshot.state.value
    scan.snapshot = snapshot.model_dump(mode="json")
    scan.finished_at = datetime.now(UTC)
    scan.duration_seconds = (scan.finished_at - utc(scan.started_at)).total_seconds()
    scan.error = "; ".join(snapshot.errors)[:3000] or None
    target.last_scan_at = scan.finished_at
    for s in snapshot.services:
        db.add(
            ScanService(
                scan_id=scan.id,
                address=s.address,
                port=s.port,
                state=s.state,
                data=s.model_dump(mode="json"),
            )
        )
    for c in snapshot.certificates:
        db.add(
            TLSCertificate(
                scan_id=scan.id,
                fingerprint=c.fingerprint,
                not_after=c.not_after,
                data=c.model_dump(mode="json"),
            )
        )
    for kind, values in snapshot.dns.items():
        db.add(DNSRecord(scan_id=scan.id, kind=kind, values=values))
    proposed = compare(
        previous,
        snapshot,
        settings.tls_warning_days,
        settings.tls_second_warning_days,
        settings.tls_critical_days,
    )
    candidates = {
        c.fingerprint: c
        for c in db.scalars(select(ChangeCandidate).where(ChangeCandidate.target_id == target.id))
    }
    confirmations = {e.fingerprint for e in proposed if e.needs_confirmation}
    for key in set(candidates) - confirmations:
        db.delete(candidates[key])
    held = False
    emit = []
    observed_keys = []
    for e in proposed:
        key = e.fingerprint
        observed_keys.append(key)
        if e.needs_confirmation:
            candidate = candidates.get(key)
            if candidate is None:
                candidate = ChangeCandidate(
                    target_id=target.id,
                    fingerprint=key,
                    observations=0,
                    last_scan_id=scan.id,
                    details=e.details,
                )
                db.add(candidate)
            candidate.observations += 1
            candidate.last_scan_id = scan.id
            if candidate.observations < settings.removal_confirmations:
                held = True
                continue
        if key in target.active_fingerprints:
            continue
        row = ChangeEvent(
            target_id=target.id,
            scan_id=scan.id,
            type=e.type,
            severity=e.severity,
            message=e.message,
            details=e.details,
            fingerprint=key,
        )
        db.add(row)
        emit.append(row)
    # Candidates do not suppress the first confirmed event.
    if snapshot.state in {ScanState.FAILED, ScanState.PARTIAL}:
        # Uncertainty cannot prove that an existing warning/change was resolved.
        target.active_fingerprints = list(
            dict.fromkeys([*target.active_fingerprints, *observed_keys])
        )
    else:
        target.active_fingerprints = [e.fingerprint for e in emit] + [
            k for k in observed_keys if k in target.active_fingerprints
        ]
    if snapshot.state == ScanState.SUCCESS and not held:
        target.baseline_scan_id = scan.id
        db.execute(delete(ChangeCandidate).where(ChangeCandidate.target_id == target.id))
    rules = db.scalars(
        select(AlertRule).where(AlertRule.owner_id == target.owner_id, AlertRule.enabled.is_(True))
    ).all()
    for rule in rules:
        selected = [e for e in emit if SEVERITIES[e.severity] >= SEVERITIES[rule.min_severity]]
        if selected:
            payload = f"SurfaceWatch · {target.name} ({target.host})\n" + "\n".join(
                f"[{e.severity}] {e.type}: {e.message}" for e in selected
            )
            db.add(Notification(rule_id=rule.id, target_id=target.id, payload=payload[:3500]))
    db.commit()
    log.info(
        "scan_completed scan_id=%s target_id=%s state=%s duration=%.2f services=%s events=%s baseline_held=%s",
        scan.id,
        target.id,
        scan.state,
        scan.duration_seconds,
        len(snapshot.services),
        len(emit),
        held,
    )
    return emit
