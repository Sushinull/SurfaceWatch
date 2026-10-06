from datetime import UTC, datetime, timedelta

import pytest

from app.diff.engine import compare
from app.scanner.types import Certificate, Service, Snapshot

NOW = datetime(2026, 10, 6, tzinfo=UTC)


def snapshot(state="SUCCESS", ports=(22, 80), states=("open", "closed"), **kwargs):
    return Snapshot(
        state=state,
        observed_at=NOW,
        addresses=["127.0.0.1"],
        ports=list(ports),
        services=[
            Service(
                address="127.0.0.1",
                port=p,
                state=s,
                name="http" if p == 80 else "ssh",
                confidence=10,
            )
            for p, s in zip(ports, states, strict=True)
        ],
        **kwargs,
    )


def kinds(events):
    return [e.type for e in events]


def cert(days=90, **kwargs):
    values = dict(
        address="127.0.0.1",
        port=443,
        hostname="example.com",
        subject="CN=example.com",
        issuer="CN=lab",
        serial="1",
        fingerprint="abc",
        not_before=NOW - timedelta(days=1),
        not_after=NOW + timedelta(days=days),
        sans=["example.com"],
        hostname_matches=True,
    )
    values.update(kwargs)
    return Certificate(**values)


def test_baseline_and_identical():
    a = snapshot()
    assert kinds(compare(None, a)) == ["INITIAL_BASELINE"]
    assert compare(a, a) == []


def test_new_and_removed():
    a, b = snapshot(), snapshot(states=("closed", "open"))
    events = compare(a, b)
    assert kinds(events) == ["REMOVED_PORT", "NEW_PORT"]
    assert events[0].needs_confirmation


@pytest.mark.parametrize("field,value", [("name", "https"), ("product", "nginx"), ("version", "2")])
def test_service_changed(field, value):
    a = snapshot()
    setattr(a.services[0], field, "old-value")
    b = a.model_copy(deep=True)
    setattr(b.services[0], field, value)
    assert kinds(compare(a, b)) == ["SERVICE_CHANGED"]


def test_lost_version_is_not_change():
    a = snapshot()
    a.services[0].version = "1.0"
    b = a.model_copy(deep=True)
    b.services[0].version = ""
    assert compare(a, b) == []


@pytest.mark.parametrize("state,kind", [("FAILED", "SCAN_FAILED"), ("PARTIAL", "SCAN_PARTIAL")])
def test_failure_never_removal(state, kind):
    assert kinds(compare(snapshot(), snapshot(state, ports=(), states=()))) == [kind]


def test_filtered_is_uncertain():
    events = compare(snapshot(), snapshot("PARTIAL", states=("filtered", "closed")))
    assert kinds(events) == ["SCAN_PARTIAL", "PORT_STATE_CHANGED"]
    assert events[-1].details["uncertain"]


def test_reordered_dns():
    a = snapshot(dns={"A": ["1.1.1.1", "8.8.8.8"], "CNAME": ["EDGE.Example.com."]})
    b = snapshot(dns={"CNAME": ["edge.example.com"], "A": ["8.8.8.8", "1.1.1.1"]})
    assert compare(a, b) == []
    b.dns["A"] = ["8.8.4.4"]
    assert kinds(compare(a, b)) == ["DNS_CHANGED"]


def test_address_removed_does_not_remove_ports():
    a = snapshot()
    b = a.model_copy(deep=True)
    b.addresses = ["127.0.0.2"]
    for svc in b.services:
        svc.address = "127.0.0.2"
    assert kinds(compare(a, b)) == ["IP_CHANGED"]


def test_profile_narrowing_never_removes():
    assert compare(snapshot(), snapshot(ports=(22,), states=("open",))) == []


@pytest.mark.parametrize(
    "days,expected",
    [
        (31, None),
        (30, "TLS_EXPIRING"),
        (14, "TLS_EXPIRING"),
        (7, "TLS_CRITICAL"),
        (1, "TLS_CRITICAL"),
        (0, "TLS_EXPIRED"),
        (-1, "TLS_EXPIRED"),
    ],
)
def test_tls_thresholds(days, expected):
    events = compare(snapshot(), snapshot(certificates=[cert(days)]))
    assert kinds(events) == ([expected] if expected else [])


def test_tls_renewal_changed_and_hostname():
    a = snapshot(certificates=[cert()])
    b = snapshot(certificates=[cert(100, fingerprint="def")])
    assert kinds(compare(a, b)) == ["TLS_RENEWED"]
    b.certificates[0].not_after = a.certificates[0].not_after
    b.certificates[0].hostname_matches = False
    assert kinds(compare(a, b)) == ["TLS_CHANGED", "TLS_HOSTNAME_MISMATCH"]


def test_service_whitespace_normalized():
    a = snapshot()
    a.services[0].product = "Open SSH"
    b = a.model_copy(deep=True)
    b.services[0].product = " open   ssh "
    assert compare(a, b) == []


def test_database_port_severity():
    a = snapshot(ports=(5432,), states=("closed",))
    b = snapshot(ports=(5432,), states=("open",))
    assert compare(a, b)[0].severity == "HIGH"
