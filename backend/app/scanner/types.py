from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class ScanState(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class Service(BaseModel):
    address: str
    port: int
    protocol: str = "tcp"
    state: str
    name: str = ""
    product: str = ""
    version: str = ""
    tunnel: str = ""
    confidence: int = 0

    @property
    def key(self) -> tuple[str, int, str]:
        return self.address, self.port, self.protocol


class Certificate(BaseModel):
    address: str
    port: int
    hostname: str
    subject: str
    issuer: str
    serial: str
    fingerprint: str
    not_before: datetime
    not_after: datetime
    sans: list[str]
    hostname_matches: bool
    chain_valid: bool = False

    @property
    def key(self) -> tuple[str, int]:
        return self.address, self.port


class Snapshot(BaseModel):
    state: ScanState
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    addresses: list[str] = Field(default_factory=list)
    dns: dict[str, list[str]] = Field(default_factory=dict)
    ports: list[int] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    certificates: list[Certificate] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    host_down_confirmed: bool = False
