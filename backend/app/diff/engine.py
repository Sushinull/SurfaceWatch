import hashlib
import json
import math

from pydantic import BaseModel, Field

from app.scanner.types import ScanState, Snapshot

SEVERITIES = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
EVENT_SEVERITY = {
    "INITIAL_BASELINE": "INFO",
    "NEW_PORT": "MEDIUM",
    "REMOVED_PORT": "MEDIUM",
    "SERVICE_CHANGED": "LOW",
    "PORT_STATE_CHANGED": "LOW",
    "IP_CHANGED": "MEDIUM",
    "DNS_CHANGED": "LOW",
    "TLS_RENEWED": "INFO",
    "TLS_CHANGED": "MEDIUM",
    "TLS_EXPIRING": "MEDIUM",
    "TLS_CRITICAL": "HIGH",
    "TLS_EXPIRED": "CRITICAL",
    "TLS_HOSTNAME_MISMATCH": "HIGH",
    "HOST_DOWN": "HIGH",
    "SCAN_FAILED": "MEDIUM",
    "SCAN_PARTIAL": "LOW",
}
DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 27017}


class Event(BaseModel):
    type: str
    severity: str = "INFO"
    message: str
    details: dict = Field(default_factory=dict)
    needs_confirmation: bool = False

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(
            json.dumps({"type": self.type, "details": self.details}, sort_keys=True).encode()
        ).hexdigest()


def event(kind: str, message: str, details: dict | None = None, confirm: bool = False) -> Event:
    details = details or {}
    severity = EVENT_SEVERITY[kind]
    if kind == "NEW_PORT" and details.get("port") in DATABASE_PORTS:
        severity = "HIGH"
    return Event(
        type=kind, severity=severity, message=message, details=details, needs_confirmation=confirm
    )


def normalized_dns(records: dict) -> dict:
    return {
        k: sorted({str(v).lower().rstrip(".") for v in values})
        for k, values in sorted(records.items())
    }


def service_signature(svc) -> tuple:
    return tuple(
        " ".join(v.lower().split()) for v in (svc.name, svc.product, svc.version, svc.tunnel)
    )


def meaningful_service_change(old, new) -> bool:
    before, after = service_signature(old), service_signature(new)
    return any(a and b and a != b for a, b in zip(before, after, strict=True))


def compare(
    previous: Snapshot | None, current: Snapshot, warning=30, second_warning=14, critical=7
) -> list[Event]:
    if current.state == ScanState.FAILED:
        return [
            event(
                "SCAN_FAILED", "Scan failed; trusted baseline retained", {"errors": current.errors}
            )
        ]
    if current.state == ScanState.PARTIAL:
        events = [
            event(
                "SCAN_PARTIAL",
                "Partial scan; trusted baseline retained",
                {"errors": current.errors},
            )
        ]
        if previous:
            before = {s.key: s for s in previous.services}
            for s in current.services:
                old = before.get(s.key)
                if old and s.state not in {"open", "closed"} and old.state != s.state:
                    events.append(
                        event(
                            "PORT_STATE_CHANGED",
                            f"Port {s.port} is uncertain ({s.state})",
                            {
                                "address": s.address,
                                "port": s.port,
                                "before": old.state,
                                "after": s.state,
                                "uncertain": True,
                            },
                        )
                    )
        return events
    if current.state != ScanState.SUCCESS:
        return []
    events = []
    if previous is None:
        events.append(event("INITIAL_BASELINE", "First complete scan established the baseline"))
    else:
        if set(previous.addresses) != set(current.addresses):
            events.append(
                event(
                    "IP_CHANGED",
                    "Resolved address set changed",
                    {
                        "before": sorted(previous.addresses),
                        "after": sorted(current.addresses),
                    },
                )
            )
        if normalized_dns(previous.dns) != normalized_dns(current.dns):
            events.append(
                event(
                    "DNS_CHANGED",
                    "DNS records changed",
                    {
                        "before": normalized_dns(previous.dns),
                        "after": normalized_dns(current.dns),
                    },
                )
            )
        # Compare only the same endpoint and overlapping port scope. Missing IPs/ports
        # mean changed coverage, not removal. Newly added IPs establish endpoint state.
        before = {s.key: s for s in previous.services}
        for svc in current.services:
            old = before.get(svc.key)
            if not old:
                if svc.state == "open" and svc.address in previous.addresses:
                    events.append(
                        event(
                            "NEW_PORT",
                            f"TCP {svc.port} became visible",
                            {"address": svc.address, "port": svc.port, "coverage_added": True},
                        )
                    )
                continue
            details = {"address": svc.address, "port": svc.port}
            if old.state != "open" and svc.state == "open":
                events.append(event("NEW_PORT", f"TCP {svc.port} became accessible", details))
            elif old.state == "open" and svc.state == "closed":
                events.append(
                    event(
                        "REMOVED_PORT", f"TCP {svc.port} is confirmed closed", details, confirm=True
                    )
                )
            elif old.state != svc.state:
                events.append(
                    event(
                        "PORT_STATE_CHANGED",
                        f"TCP {svc.port}: {old.state} → {svc.state}",
                        {**details, "before": old.state, "after": svc.state},
                    )
                )
            elif (
                svc.state == "open"
                and old.confidence >= 3
                and svc.confidence >= 3
                and meaningful_service_change(old, svc)
            ):
                # Loss of a product/version is scanner uncertainty, not an upgrade.
                if (old.product and not svc.product) or (old.version and not svc.version):
                    continue
                events.append(
                    event(
                        "SERVICE_CHANGED",
                        f"Service on TCP {svc.port} changed",
                        {
                            **details,
                            "before": service_signature(old),
                            "after": service_signature(svc),
                        },
                    )
                )
        old_certs = {c.key: c for c in previous.certificates}
        for cert in current.certificates:
            old = old_certs.get(cert.key)
            if old and old.fingerprint != cert.fingerprint:
                kind = "TLS_RENEWED" if cert.not_after > old.not_after else "TLS_CHANGED"
                events.append(
                    event(
                        kind,
                        f"Certificate on TCP {cert.port} changed",
                        {
                            "address": cert.address,
                            "port": cert.port,
                            "before": old.fingerprint,
                            "after": cert.fingerprint,
                        },
                    )
                )
    for cert in current.certificates:
        # ceil: a certificate expiring in 23h has 1 day remaining; exact expiry is expired.
        days = math.ceil((cert.not_after - current.observed_at).total_seconds() / 86400)
        details = {"address": cert.address, "port": cert.port, "fingerprint": cert.fingerprint}
        if days <= 0:
            events.append(
                event(
                    "TLS_EXPIRED",
                    f"TLS certificate on TCP {cert.port} expired",
                    {**details, "threshold": 0},
                )
            )
        elif days <= critical:
            events.append(
                event(
                    "TLS_CRITICAL",
                    f"TLS certificate expires within {critical} days",
                    {**details, "threshold": critical},
                )
            )
        elif days <= warning:
            threshold = second_warning if days <= second_warning else warning
            events.append(
                event(
                    "TLS_EXPIRING",
                    f"TLS certificate expires within {threshold} days",
                    {**details, "threshold": threshold},
                )
            )
        if not cert.hostname_matches:
            events.append(
                event(
                    "TLS_HOSTNAME_MISMATCH",
                    f"Certificate does not match {cert.hostname}",
                    {**details, "hostname": cert.hostname},
                )
            )
    if current.host_down_confirmed:
        events.append(
            event("HOST_DOWN", "Host down confirmed by an independent reachability check")
        )
    return events
