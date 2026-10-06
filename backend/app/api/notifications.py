import re

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import RuleInput, RuleOut
from app.core.auth import current_user
from app.core.config import get_settings
from app.db.models import AlertRule, Notification, User
from app.db.session import get_db

router = APIRouter(prefix="/notifications", tags=["Notifications"])


def rule_owned(db, user, rule_id):
    rule = db.get(AlertRule, rule_id)
    if not rule or rule.owner_id != user.id:
        raise HTTPException(404, "Notification rule not found")
    return rule


def validate_rule(data):
    if data.channel == "smtp" and not re.fullmatch(r"[^\s@]+@[^\s@]+", data.destination):
        raise HTTPException(422, "Enter an email recipient for SMTP")


@router.get("/config")
def config(user: User = Depends(current_user)):
    s = get_settings()
    return {
        "smtp": bool(s.smtp_host),
        "telegram": bool(s.telegram_bot_token and s.telegram_chat_id),
        "discord": bool(s.discord_webhook_url),
    }


@router.get("/rules", response_model=list[RuleOut])
def rules(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return db.scalars(
        select(AlertRule).where(AlertRule.owner_id == user.id).order_by(AlertRule.id)
    ).all()


@router.post("/rules", status_code=201, response_model=RuleOut)
def create_rule(data: RuleInput, db: Session = Depends(get_db), user: User = Depends(current_user)):
    validate_rule(data)
    # Serialize this owner's count + insert so simultaneous requests cannot exceed
    # the advertised cap. PostgreSQL is the deployment database.
    db.scalar(select(User).where(User.id == user.id).with_for_update())
    count = len(db.scalars(select(AlertRule).where(AlertRule.owner_id == user.id)).all())
    if count >= 10:
        raise HTTPException(409, "Maximum 10 notification rules")
    rule = AlertRule(owner_id=user.id, **data.model_dump())
    db.add(rule)
    db.commit()
    return rule


@router.put("/rules/{rule_id}", response_model=RuleOut)
def update_rule(
    rule_id: int, data: RuleInput, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    validate_rule(data)
    rule = rule_owned(db, user, rule_id)
    for k, v in data.model_dump().items():
        setattr(rule, k, v)
    db.commit()
    return rule


@router.post("/rules/{rule_id}/test", status_code=202)
def test_rule(rule_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    rule = rule_owned(db, user, rule_id)
    if not rule.enabled:
        raise HTTPException(409, "Enable the rule before testing")
    note = Notification(
        rule_id=rule.id, payload="SurfaceWatch test notification: delivery path is working."
    )
    db.add(note)
    db.commit()
    return {"id": note.id, "state": note.state}


@router.get("")
def history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    notes = db.scalars(
        select(Notification)
        .join(AlertRule)
        .where(AlertRule.owner_id == user.id)
        .order_by(Notification.id.desc())
        .offset(offset)
        .limit(limit)
    )
    return [
        {
            "id": n.id,
            "rule_id": n.rule_id,
            "state": n.state,
            "attempts": n.attempts,
            "error": n.error,
            "created_at": n.created_at,
            "sent_at": n.sent_at,
            "payload": n.payload,
        }
        for n in notes
    ]
