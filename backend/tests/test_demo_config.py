from pathlib import Path
from unittest.mock import patch

import yaml

from app.core.config import get_settings

ROOT = Path(__file__).resolve().parents[2]


def test_demo_network_and_notification_configuration(logged_in):
    base = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    demo = yaml.safe_load((ROOT / "docker-compose.demo.yml").read_text())
    services = demo["services"]
    assert base["networks"]["lab"]["internal"] is True
    assert set(services["lab"]["networks"]) == {"lab"}
    assert "ports" not in services["lab"]
    assert set(services["mailpit"]["networks"]) == {"lab", "default"}
    assert services["mailpit"]["ports"] == ["127.0.0.1:8025:8025"]
    api_env = services["backend"]["environment"]
    assert api_env == services["worker"]["environment"]
    assert api_env["SMTP_HOST"] == "mailpit" and api_env["SMTP_PORT"] == 1025
    settings = get_settings().model_copy(
        update={
            "smtp_host": api_env["SMTP_HOST"],
            "smtp_password": "must-not-leak",
            "telegram_bot_token": "must-not-leak",
            "telegram_chat_id": "demo-chat",
            "discord_webhook_url": "https://discord.com/api/webhooks/demo/must-not-leak",
        }
    )
    with patch("app.api.notifications.get_settings", return_value=settings):
        response = logged_in.get("/api/notifications/config")
    assert response.json() == {"smtp": True, "telegram": True, "discord": True}
    assert "must-not-leak" not in response.text


def test_unconfigured_channels_are_false(logged_in):
    settings = get_settings().model_copy(
        update={"smtp_host": "", "telegram_bot_token": "", "discord_webhook_url": ""}
    )
    with patch("app.api.notifications.get_settings", return_value=settings):
        assert logged_in.get("/api/notifications/config").json() == {
            "smtp": False,
            "telegram": False,
            "discord": False,
        }
