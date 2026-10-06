import logging
import smtplib
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from urllib.parse import urlparse

import httpx
from sqlalchemy import select

from app.core.config import Settings
from app.db.models import AlertRule, Notification

log = logging.getLogger(__name__)


def send_notification(channel: str, destination: str, payload: str, settings: Settings):
    if channel == "smtp":
        if not settings.smtp_host or not destination or any(c in destination for c in "\r\n"):
            raise ValueError("SMTP configuration incomplete")
        if not settings.smtp_starttls and not settings.smtp_allow_plaintext:
            raise ValueError("Plain SMTP requires explicit SMTP_ALLOW_PLAINTEXT for the demo lab")
        message = EmailMessage()
        message["Subject"] = "SurfaceWatch change alert"
        message["From"] = settings.smtp_from
        message["To"] = destination
        message.set_content(payload)
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            if settings.smtp_starttls:
                smtp.starttls()
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(message)
    elif channel == "telegram":
        if not settings.telegram_bot_token or not settings.telegram_chat_id:
            raise ValueError("Telegram configuration incomplete")
        with httpx.Client(timeout=10, follow_redirects=False, trust_env=False) as client:
            response = client.post(
                f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage",
                json={"chat_id": settings.telegram_chat_id, "text": payload},
            )
            if response.status_code != 200 or not response.json().get("ok"):
                raise ValueError("Telegram rejected notification")
    elif channel == "discord":
        url = urlparse(settings.discord_webhook_url)
        if (
            url.scheme != "https"
            or url.hostname not in {"discord.com", "discordapp.com"}
            or not url.path.startswith("/api/webhooks/")
        ):
            raise ValueError("Invalid Discord webhook configuration")
        with httpx.Client(timeout=10, follow_redirects=False, trust_env=False) as client:
            response = client.post(
                settings.discord_webhook_url,
                json={"content": payload[:1900], "allowed_mentions": {"parse": []}},
            )
            if response.status_code not in {200, 204}:
                raise ValueError("Discord rejected notification")
    else:
        raise ValueError("Unsupported notification channel")


def dispatch_notifications(db, settings: Settings):
    pending = db.scalars(
        select(Notification)
        .where(Notification.state == "PENDING", Notification.next_attempt_at <= datetime.now(UTC))
        .order_by(Notification.id)
        .limit(10)
    ).all()
    for note in pending:
        rule = db.get(AlertRule, note.rule_id)
        if not rule.enabled:
            note.state = "CANCELLED"
            db.commit()
            continue
        note.attempts += 1
        try:
            send_notification(rule.channel, rule.destination, note.payload, settings)
            note.state = "SENT"
            note.sent_at = datetime.now(UTC)
            note.error = None
        except Exception as exc:
            # Exception text from HTTP/SMTP libraries may contain tokens or credentials.
            note.error = f"Delivery failed: {type(exc).__name__}"
            if note.attempts >= 3:
                note.state = "FAILED"
            else:
                note.next_attempt_at = datetime.now(UTC) + timedelta(seconds=60 * note.attempts)
        db.commit()
        log.info("notification id=%s state=%s attempts=%s", note.id, note.state, note.attempts)
