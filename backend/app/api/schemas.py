from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.validation import normalize_target, validate_ports


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginInput(Input):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class TargetInput(Input):
    name: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=253)
    profile_id: int = Field(gt=0)
    interval_seconds: int = Field(default=3600, ge=300, le=2592000)
    enabled: bool = True
    authorized: Literal[True]

    @field_validator("host")
    @classmethod
    def target(cls, value):
        return normalize_target(value)

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, value):
        if not value.strip():
            raise ValueError("Name cannot be blank")
        return value.strip()


class ProfileInput(Input):
    name: str = Field(min_length=1, max_length=80)
    ports: list[int] = Field(min_length=1, max_length=1024)
    description: str = Field(default="", max_length=300)

    @field_validator("ports")
    @classmethod
    def ports_valid(cls, value):
        return validate_ports(value)


class RuleInput(Input):
    channel: Literal["smtp", "telegram", "discord"]
    destination: str = Field(default="", max_length=254)
    min_severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    enabled: bool = True

    @field_validator("destination")
    @classmethod
    def no_headers(cls, value):
        if "\r" in value or "\n" in value:
            raise ValueError("Invalid destination")
        return value


class Record(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class UserOut(Record):
    id: int
    username: str


class ProfileOut(Record):
    id: int
    name: str
    ports: list[int]
    description: str


class RuleOut(RuleInput, Record):
    id: int


class EventOut(Record):
    id: int
    target_id: int
    scan_id: int
    type: str
    severity: str
    message: str
    details: dict
    acknowledged: bool
    created_at: datetime


class TargetOut(Record):
    id: int
    name: str
    host: str
    profile_id: int
    enabled: bool
    authorized: bool
    archived: bool
    interval_seconds: int
    next_scan_at: datetime | None
    last_scan_at: datetime | None
    baseline_scan_id: int | None
    status: str
    latest_scan_state: str | None
    latest_event: EventOut | None
    pending_changes: list[dict]


class TargetDetailOut(TargetOut):
    trusted_snapshot: dict | None
    services: list[dict]
    certificates: list[dict]
    addresses: list[str]
    dns: dict


class ScanOut(Record):
    id: int
    target_id: int
    target_host: str
    state: str
    source: str
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: float | None
    error: str | None
    ports: list[int]


class ScanDetailOut(ScanOut):
    snapshot: dict | None


class DashboardOut(Record):
    total_targets: int
    monitored_targets: int
    healthy_targets: int
    attention_targets: int
    recent_events: list[EventOut]
    targets: list[TargetOut]
    tls_warnings: list[dict]
