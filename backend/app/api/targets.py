import math
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.schemas import (
    ProfileInput,
    ProfileOut,
    ScanDetailOut,
    ScanOut,
    TargetDetailOut,
    TargetInput,
    TargetOut,
)
from app.core.auth import current_user
from app.core.config import get_settings
from app.db.models import ChangeCandidate, ChangeEvent, Scan, ScanProfile, Target, User
from app.db.session import get_db
from app.scanner.types import Snapshot
from app.services.scans import enqueue

router = APIRouter(tags=["Targets and scans"])


def owned_target(db, user, target_id, include_archived=False, lock=False):
    query = select(Target).where(Target.id == target_id)
    target = db.scalar(query.with_for_update() if lock else query)
    if target is None or target.owner_id != user.id or (target.archived and not include_archived):
        raise HTTPException(404, "Target not found")
    return target


def target_view(db, target):
    last = db.scalar(
        select(Scan).where(Scan.target_id == target.id).order_by(Scan.id.desc()).limit(1)
    )
    latest = db.scalar(
        select(ChangeEvent)
        .where(ChangeEvent.target_id == target.id)
        .order_by(ChangeEvent.id.desc())
        .limit(1)
    )
    baseline = db.get(Scan, target.baseline_scan_id) if target.baseline_scan_id else None
    pending = db.scalars(
        select(ChangeCandidate).where(ChangeCandidate.target_id == target.id)
    ).all()
    status = "Awaiting baseline"
    if baseline:
        status = "Healthy"
    if latest and not latest.acknowledged and latest.severity in {"MEDIUM", "HIGH", "CRITICAL"}:
        status = "Changes detected"
    if baseline and any(
        (c.not_after - datetime.now(UTC)).total_seconds() <= get_settings().tls_warning_days * 86400
        or not c.hostname_matches
        for c in Snapshot.model_validate(baseline.snapshot).certificates
    ):
        status = "TLS warning"
    if last and last.state in {"FAILED", "PARTIAL"}:
        status = "Scan failed" if last.state == "FAILED" else "Partial scan"
    if pending:
        status = "Confirming closure"
    if not target.enabled:
        status = "Monitoring disabled"
    if target.archived:
        status = "Archived"
    return {
        "id": target.id,
        "name": target.name,
        "host": target.host,
        "profile_id": target.profile_id,
        "enabled": target.enabled,
        "authorized": target.authorized,
        "archived": target.archived,
        "interval_seconds": target.interval_seconds,
        "next_scan_at": target.next_scan_at if target.enabled and not target.archived else None,
        "last_scan_at": target.last_scan_at,
        "baseline_scan_id": target.baseline_scan_id,
        "status": status,
        "latest_scan_state": last.state if last else None,
        "latest_event": event_view(latest) if latest else None,
        "pending_changes": [
            {"observations": c.observations, "details": c.details} for c in pending
        ],
    }


def scan_view(scan, detail=False):
    data = {
        "id": scan.id,
        "target_id": scan.target_id,
        "target_host": scan.target_host,
        "state": scan.state,
        "source": scan.source,
        "queued_at": scan.queued_at,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "duration_seconds": scan.duration_seconds,
        "error": scan.error,
        "ports": scan.ports,
    }
    if detail:
        data["snapshot"] = scan.snapshot
    return data


def event_view(e):
    return {
        "id": e.id,
        "target_id": e.target_id,
        "scan_id": e.scan_id,
        "type": e.type,
        "severity": e.severity,
        "message": e.message,
        "details": e.details,
        "acknowledged": e.acknowledged,
        "created_at": e.created_at,
    }


@router.get("/profiles", response_model=list[ProfileOut])
def profiles(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return db.scalars(select(ScanProfile).order_by(ScanProfile.id)).all()


@router.post("/profiles", status_code=201, response_model=ProfileOut)
def create_profile(
    data: ProfileInput, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    profile = ScanProfile(**data.model_dump())
    db.add(profile)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Profile name already exists") from None
    return profile


@router.get("/targets", response_model=list[TargetOut])
def targets(
    archived: bool = False, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    return [
        target_view(db, t)
        for t in db.scalars(
            select(Target)
            .where(Target.owner_id == user.id, Target.archived == archived)
            .order_by(Target.id)
        )
    ]


def check_profile(db, profile_id):
    if not db.get(ScanProfile, profile_id):
        raise HTTPException(422, "Unknown scan profile")


@router.post("/targets", status_code=201, response_model=TargetOut)
def create_target(
    data: TargetInput, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    check_profile(db, data.profile_id)
    if db.scalar(
        select(Target).where(
            Target.owner_id == user.id, Target.host == data.host, Target.archived.is_(False)
        )
    ):
        raise HTTPException(409, "An active target with this host already exists")
    target = Target(
        owner_id=user.id,
        **data.model_dump(),
        next_scan_at=datetime.now(UTC) + timedelta(seconds=data.interval_seconds),
    )
    db.add(target)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "An active target with this host already exists") from None
    return target_view(db, target)


@router.put("/targets/{target_id}", response_model=TargetOut)
def update_target(
    target_id: int,
    data: TargetInput,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    target = owned_target(db, user, target_id, lock=True)
    if db.scalar(
        select(Scan).where(Scan.target_id == target.id, Scan.state.in_(["PENDING", "RUNNING"]))
    ):
        raise HTTPException(409, "Wait for the active scan before editing this target")
    check_profile(db, data.profile_id)
    if db.scalar(
        select(Target).where(
            Target.owner_id == user.id,
            Target.host == data.host,
            Target.archived.is_(False),
            Target.id != target.id,
        )
    ):
        raise HTTPException(409, "An active target with this host already exists")
    if target.host != data.host or target.profile_id != data.profile_id:
        target.baseline_scan_id = None
        target.active_fingerprints = []
        for c in db.scalars(select(ChangeCandidate).where(ChangeCandidate.target_id == target.id)):
            db.delete(c)
    for key, value in data.model_dump().items():
        setattr(target, key, value)
    target.next_scan_at = datetime.now(UTC) + timedelta(seconds=target.interval_seconds)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "An active target with this host already exists") from None
    return target_view(db, target)


@router.delete("/targets/{target_id}", status_code=204)
def archive_target(
    target_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    target = owned_target(db, user, target_id, lock=True)
    if db.scalar(
        select(Scan).where(Scan.target_id == target.id, Scan.state.in_(["PENDING", "RUNNING"]))
    ):
        raise HTTPException(409, "Wait for the active scan before archiving")
    target.archived = True
    target.enabled = False
    target.next_scan_at = None
    db.commit()


@router.get("/targets/{target_id}", response_model=TargetDetailOut)
def detail(target_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    target = owned_target(db, user, target_id, True)
    baseline = db.get(Scan, target.baseline_scan_id) if target.baseline_scan_id else None
    snapshot = Snapshot.model_validate(baseline.snapshot) if baseline else None
    return {
        **target_view(db, target),
        "trusted_snapshot": snapshot.model_dump(mode="json") if snapshot else None,
        "services": [s.model_dump() for s in snapshot.services if s.state == "open"]
        if snapshot
        else [],
        "certificates": [
            {
                **c.model_dump(mode="json"),
                "days_remaining": math.ceil(
                    (c.not_after - datetime.now(UTC)).total_seconds() / 86400
                ),
            }
            for c in snapshot.certificates
        ]
        if snapshot
        else [],
        "addresses": snapshot.addresses if snapshot else [],
        "dns": snapshot.dns if snapshot else {},
    }


@router.post("/targets/{target_id}/scans", status_code=202, response_model=ScanOut)
def manual_scan(target_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    target = owned_target(db, user, target_id, lock=True)
    job = enqueue(db, target, db.get(ScanProfile, target.profile_id).ports)
    if job is None:
        raise HTTPException(409, "A scan for this target is already queued or running")
    db.commit()
    return scan_view(job)


@router.get("/scans", response_model=list[ScanOut])
def scans(
    target_id: int | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = select(Scan).join(Target, Scan.target_id == Target.id).where(Target.owner_id == user.id)
    if target_id is not None:
        query = query.where(Scan.target_id == target_id)
    return [
        scan_view(s) for s in db.scalars(query.order_by(Scan.id.desc()).offset(offset).limit(limit))
    ]


@router.get("/scans/{scan_id}", response_model=ScanDetailOut)
def scan_detail(scan_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    owned_target(db, user, scan.target_id, True)
    return scan_view(scan, True)
