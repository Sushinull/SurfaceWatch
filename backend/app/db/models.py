from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

Json = JSON().with_variant(JSONB(), "postgresql")


def now():
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class ScanProfile(Base):
    __tablename__ = "scan_profiles"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    ports: Mapped[list] = mapped_column(Json)
    description: Mapped[str] = mapped_column(String(300), default="")


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    host: Mapped[str] = mapped_column(String(253))
    profile_id: Mapped[int] = mapped_column(ForeignKey("scan_profiles.id"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    authorized: Mapped[bool] = mapped_column(Boolean)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    next_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    baseline_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", use_alter=True, name="fk_target_baseline")
    )
    active_fingerprints: Mapped[list] = mapped_column(Json, default=list)
    __table_args__ = (
        Index("ix_targets_owner_host", "owner_id", "host"),
        Index(
            "uq_targets_active_owner_host",
            "owner_id",
            "host",
            unique=True,
            postgresql_where=text("archived = false"),
            sqlite_where=text("archived = 0"),
        ),
    )


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    state: Mapped[str] = mapped_column(String(16), default="PENDING")
    source: Mapped[str] = mapped_column(String(16), default="manual")
    target_host: Mapped[str] = mapped_column(String(253))
    ports: Mapped[list] = mapped_column(Json)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[float | None]
    error: Mapped[str | None] = mapped_column(Text)
    snapshot: Mapped[dict | None] = mapped_column(Json)
    __table_args__ = (
        Index("ix_scans_target_queued", "target_id", "queued_at"),
        Index(
            "uq_scans_active_target",
            "target_id",
            unique=True,
            postgresql_where=text("state IN ('PENDING','RUNNING')"),
            sqlite_where=text("state IN ('PENDING','RUNNING')"),
        ),
    )


class ScanService(Base):
    __tablename__ = "scan_services"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    address: Mapped[str] = mapped_column(String(45))
    port: Mapped[int]
    state: Mapped[str] = mapped_column(String(24))
    data: Mapped[dict] = mapped_column(Json)


class TLSCertificate(Base):
    __tablename__ = "tls_certificates"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    data: Mapped[dict] = mapped_column(Json)


class DNSRecord(Base):
    __tablename__ = "dns_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    kind: Mapped[str] = mapped_column(String(10))
    values: Mapped[list] = mapped_column(Json)


class ChangeEvent(Base):
    __tablename__ = "change_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    type: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    message: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(Json)
    fingerprint: Mapped[str] = mapped_column(String(64))
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class ChangeCandidate(Base):
    __tablename__ = "change_candidates"
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    observations: Mapped[int] = mapped_column(default=0)
    last_scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    details: Mapped[dict] = mapped_column(Json)


class AlertRule(Base):
    __tablename__ = "alert_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    channel: Mapped[str] = mapped_column(String(16))
    destination: Mapped[str] = mapped_column(String(254), default="")
    min_severity: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("alert_rules.id"))
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id"))
    payload: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(16), default="PENDING")
    attempts: Mapped[int] = mapped_column(default=0)
    error: Mapped[str | None] = mapped_column(String(100))
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
