from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=("../.env", ".env"), extra="ignore")
    database_url: str = "postgresql+psycopg://surfacewatch:surfacewatch@localhost/surfacewatch"
    secret_key: str = Field(min_length=32)
    allowed_target_cidrs: str = ""
    max_target_addresses: int = Field(default=8, ge=1, le=32)
    scan_timeout: int = Field(default=180, ge=10, le=1800)
    tls_timeout: int = Field(default=5, ge=1, le=30)
    removal_confirmations: int = Field(default=2, ge=1, le=5)
    tls_warning_days: int = Field(default=30, ge=1, le=365)
    tls_second_warning_days: int = Field(default=14, ge=1, le=365)
    tls_critical_days: int = Field(default=7, ge=1, le=365)
    session_hours: int = Field(default=8, ge=1, le=72)
    cookie_secure: bool = False
    app_origin: str = "http://localhost:8080"
    worker_poll_seconds: int = Field(default=3, ge=1, le=60)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "surfacewatch@localhost"
    smtp_starttls: bool = True
    smtp_allow_plaintext: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    discord_webhook_url: str = ""

    @model_validator(mode="after")
    def thresholds(self):
        if not self.tls_critical_days <= self.tls_second_warning_days <= self.tls_warning_days:
            raise ValueError("TLS thresholds must be critical <= second warning <= warning")
        if self.secret_key.lower().startswith(("change", "replace", "example")):
            raise ValueError("Generate a real SECRET_KEY with scripts/setup.py")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
