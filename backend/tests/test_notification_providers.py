from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from app.core.config import get_settings
from app.db.models import AlertRule, ChangeEvent, Notification, Scan
from app.services.notifications import dispatch_notifications, send_notification
from app.worker import tick
from tests.test_diff import snapshot
from tests.test_persistence import make_target, run


@pytest.mark.parametrize(
    "channel,status,body,accepted",
    [
        ("telegram", 200, {"ok": True}, True),
        ("telegram", 200, {"ok": False}, False),
        ("telegram", 429, {}, False),
        ("telegram", 500, {}, False),
        ("discord", 204, {}, True),
        ("discord", 302, {}, False),
        ("discord", 429, {}, False),
    ],
)
def test_http_providers_fixed_destination_no_redirects_or_mentions(channel, status, body, accepted):
    settings = get_settings().model_copy(
        update={
            "telegram_bot_token": "fake-token",
            "telegram_chat_id": "fake-chat",
            "discord_webhook_url": "https://discord.com/api/webhooks/1/fake",
        }
    )
    requests = []

    def reply(request):
        requests.append(request)
        return httpx.Response(status, json=body, headers={"Location": "http://127.0.0.1/private"})

    real_client = httpx.Client

    def client(**kwargs):
        assert kwargs == dict(timeout=10, follow_redirects=False, trust_env=False)
        return real_client(transport=httpx.MockTransport(reply), **kwargs)

    with patch("app.services.notifications.httpx.Client", side_effect=client):
        if accepted:
            send_notification(
                channel, "http://untrusted.invalid", "@everyone " + "a" * 2500, settings
            )
        else:
            with pytest.raises(ValueError):
                send_notification(channel, "ignored", "@everyone " + "a" * 2500, settings)
    assert len(requests) == 1
    assert requests[0].url.host == ("api.telegram.org" if channel == "telegram" else "discord.com")
    if channel == "discord":
        import json

        payload = json.loads(requests[0].content)
        assert payload["allowed_mentions"] == {"parse": []} and len(payload["content"]) == 1900


@pytest.mark.parametrize(
    "url",
    [
        "http://discord.com/api/webhooks/1/fake",
        "https://discord.com.evil.invalid/api/webhooks/1/fake",
        "https://127.0.0.1/api/webhooks/1/fake",
        "https://discord.com/not-webhooks",
    ],
)
def test_discord_rejects_wrong_origin_before_network(url):
    with patch("app.services.notifications.httpx.Client") as client:
        with pytest.raises(ValueError):
            send_notification(
                "discord",
                "",
                "test",
                get_settings().model_copy(update={"discord_webhook_url": url}),
            )
    client.assert_not_called()


def test_smtp_tls_login_and_plaintext_guard():
    settings = get_settings().model_copy(
        update={
            "smtp_host": "fixture.invalid",
            "smtp_user": "test-user",
            "smtp_password": "fake-secret",
            "smtp_starttls": True,
        }
    )
    with patch("app.services.notifications.smtplib.SMTP") as smtp:
        send_notification("smtp", "receiver@example.test", "message", settings)
        connection = smtp.return_value.__enter__.return_value
        connection.starttls.assert_called_once()
        connection.login.assert_called_once_with("test-user", "fake-secret")
        connection.send_message.assert_called_once()
    with patch("app.services.notifications.smtplib.SMTP") as smtp, pytest.raises(ValueError):
        send_notification(
            "smtp",
            "receiver@example.test",
            "message",
            settings.model_copy(update={"smtp_starttls": False, "smtp_allow_plaintext": False}),
        )
    smtp.assert_not_called()


def test_severity_disabled_rules_and_retry_deadline(session_factory):
    with session_factory() as db:
        target = make_target(db)
        db.add_all(
            [
                AlertRule(
                    owner_id=1, channel="smtp", destination="low@example.test", min_severity="LOW"
                ),
                AlertRule(
                    owner_id=1,
                    channel="smtp",
                    destination="critical@example.test",
                    min_severity="CRITICAL",
                ),
                AlertRule(
                    owner_id=1,
                    channel="smtp",
                    destination="disabled@example.test",
                    min_severity="INFO",
                    enabled=False,
                ),
            ]
        )
        db.commit()
        run(db, target)
        assert not db.scalars(select(Notification)).all()
        run(db, target, "FAILED")
        assert len(db.scalars(select(Notification)).all()) == 1
        note = db.scalar(select(Notification))
        before = datetime.now(UTC)
        with patch(
            "app.services.notifications.send_notification",
            side_effect=httpx.ConnectError("fake-secret-url"),
        ) as send:
            dispatch_notifications(db, get_settings())
            dispatch_notifications(db, get_settings())
            assert send.call_count == 1
        next_at = (
            note.next_attempt_at.replace(tzinfo=UTC)
            if note.next_attempt_at.tzinfo is None
            else note.next_attempt_at
        )
        assert 59 <= (next_at - before).total_seconds() <= 65
        assert note.error == "Delivery failed: ConnectError"


def test_delivery_acceptance_then_commit_failure_is_at_least_once(session_factory):
    with session_factory() as db:
        rule = AlertRule(owner_id=1, channel="smtp", destination="lab@example.test")
        db.add(rule)
        db.flush()
        db.add(Notification(rule_id=rule.id, payload="test"))
        db.commit()
    delivered = MagicMock()
    with session_factory() as db, patch("app.services.notifications.send_notification", delivered):
        with patch.object(db, "commit", side_effect=OperationalError("commit", {}, Exception())):
            with pytest.raises(OperationalError):
                dispatch_notifications(db, get_settings())
        db.rollback()
    with session_factory() as db, patch("app.services.notifications.send_notification", delivered):
        dispatch_notifications(db, get_settings())
        assert db.scalar(select(Notification.state)) == "SENT"
    assert delivered.call_count == 2  # Deliberately documented, not exactly-once delivery.


def test_exception_after_completion_commit_does_not_recover_or_duplicate(session_factory):
    from app.services.scans import enqueue, finish_scan

    with session_factory() as db:
        target = make_target(db)
        enqueue(db, target, [22, 80])
        db.commit()

    def complete_then_interrupt(*args):
        finish_scan(*args)
        raise OperationalError("after commit", {}, Exception())

    with patch("app.worker.finish_scan", side_effect=complete_then_interrupt):
        with pytest.raises(OperationalError):
            tick(session_factory, get_settings(), lambda *_: snapshot())
    tick(session_factory, get_settings(), lambda *_: snapshot())
    with session_factory() as db:
        assert db.scalar(select(Scan.state)) == "SUCCESS"
        assert [e.type for e in db.scalars(select(ChangeEvent))] == ["INITIAL_BASELINE"]
