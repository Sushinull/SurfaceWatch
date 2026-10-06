from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import DashboardOut, EventOut
from app.api.targets import event_view, target_view
from app.core.auth import current_user
from app.db.models import ChangeEvent, Target, User
from app.db.session import get_db

router = APIRouter(tags=["Events and dashboard"])


@router.get("/events", response_model=list[EventOut])
def events(
    target_id: int | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = select(ChangeEvent).join(Target).where(Target.owner_id == user.id)
    if target_id is not None:
        query = query.where(ChangeEvent.target_id == target_id)
    if event_type:
        query = query.where(ChangeEvent.type == event_type)
    if severity:
        query = query.where(ChangeEvent.severity == severity)
    if since:
        query = query.where(ChangeEvent.created_at >= since)
    if until:
        query = query.where(ChangeEvent.created_at <= until)
    return [
        event_view(e)
        for e in db.scalars(query.order_by(ChangeEvent.id.desc()).offset(offset).limit(limit))
    ]


@router.post("/events/{event_id}/acknowledge", response_model=EventOut)
def acknowledge(event_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    e = db.scalar(
        select(ChangeEvent)
        .join(Target)
        .where(ChangeEvent.id == event_id, Target.owner_id == user.id)
    )
    if not e:
        raise HTTPException(404, "Event not found")
    e.acknowledged = True
    db.commit()
    return event_view(e)


@router.get("/dashboard", response_model=DashboardOut)
def dashboard(db: Session = Depends(get_db), user: User = Depends(current_user)):
    targets = [
        target_view(db, t)
        for t in db.scalars(
            select(Target).where(Target.owner_id == user.id, Target.archived.is_(False))
        )
    ]
    monitored = [t for t in targets if t["enabled"]]
    recent = events(limit=10, offset=0, db=db, user=user)
    tls = db.scalars(
        select(ChangeEvent)
        .join(Target)
        .where(
            Target.owner_id == user.id,
            Target.archived.is_(False),
            ChangeEvent.type.in_(
                ["TLS_EXPIRING", "TLS_CRITICAL", "TLS_EXPIRED", "TLS_HOSTNAME_MISMATCH"]
            ),
            ChangeEvent.acknowledged.is_(False),
        )
        .order_by(ChangeEvent.id.desc())
        .limit(20)
    ).all()
    return {
        "total_targets": len(targets),
        "monitored_targets": len(monitored),
        "healthy_targets": sum(t["status"] == "Healthy" for t in monitored),
        "attention_targets": sum(
            t["status"] not in {"Healthy", "Awaiting baseline"} for t in monitored
        ),
        "recent_events": recent,
        "targets": targets,
        "tls_warnings": [event_view(e) for e in tls],
    }
