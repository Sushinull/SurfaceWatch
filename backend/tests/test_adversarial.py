"""Bounded, deterministic adversarial checks; no external targets/providers."""

import random
import subprocess
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import patch

import dns.exception
import dns.resolver
import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.validation import address_allowed, normalize_target, validate_ports
from app.db.models import ChangeCandidate, Target
from app.diff.engine import compare
from app.scanner.dns import resolve_target
from app.scanner.pipeline import execute_scan
from app.scanner.tls import parse_certificate
from app.scanner.types import Service, Snapshot
from app.services.scans import enqueue, finish_scan
from app.worker import schedule_due
from tests.test_api import add_target
from tests.test_diff import NOW, cert, kinds, snapshot
from tests.test_persistence import make_target, run


@pytest.mark.parametrize(
    "host",
    [
        "0",
        "2130706433",
        "0177.0.0.1",
        "example.com:443",
        "::1/128",
        "a..b",
        "a" * 64 + ".com",
        "a\x00.com",
        "a\\b",
        "x@y",
    ],
)
def test_more_invalid_host_syntax(host):
    with pytest.raises(ValueError):
        normalize_target(host)


def test_unicode_and_idempotent_normalization():
    assert normalize_target(" BÜCHER.Example. ") == "xn--bcher-kva.example"
    for host in (" EXAMPLE.COM. ", "2001:0DB8:0:0::1", "::ffff:127.0.0.1", "lab"):
        assert normalize_target(normalize_target(host)) == normalize_target(host)


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
        "169.254.169.254",
        "::ffff:169.254.169.254",
        "::ffff:0.0.0.0",
        "::ffff:224.0.0.1",
    ],
)
def test_hard_denials_survive_broad_cidr(address):
    assert not address_allowed(address, "0.0.0.0/0,::/0")


@pytest.mark.parametrize(
    "address,cidr",
    [
        ("127.0.0.1", "127.0.0.0/8"),
        ("::1", "::1/128"),
        ("169.254.1.2", "169.254.1.0/24"),
        ("fe80::1", "fe80::/64"),
        ("10.1.2.3", "10.1.2.0/24"),
        ("::ffff:127.0.0.1", "::ffff:127.0.0.1/128"),
    ],
)
def test_private_targets_require_explicit_authorization(address, cidr):
    assert not address_allowed(address, "")
    assert address_allowed(address, cidr)
    assert not address_allowed(address, "192.168.0.0/24")


@pytest.mark.parametrize("ports", [[], [0], [65536], list(range(1, 1026))])
def test_ports_outside_bounds(ports):
    with pytest.raises(ValueError):
        validate_ports(ports)


def test_seeded_normalization_and_diff_invariants():
    rng = random.Random(20261006)
    original = snapshot(
        dns={"A": ["1.1.1.1", "8.8.8.8"], "CNAME": ["edge.example.com"]},
        certificates=[cert(sans=["example.com", "www.example.com"])],
    )
    original.services[0].product = "Open SSH"
    for _ in range(100):
        ports = rng.choices(range(1, 65536), k=100)
        result = validate_ports(ports)
        assert set(result) == set(ports) and result == sorted(result)
        current = original.model_copy(deep=True)
        rng.shuffle(current.services)
        rng.shuffle(current.ports)
        current.observed_at += timedelta(seconds=rng.randrange(1, 3600))
        current.dns["A"] = ["8.8.8.8", "1.1.1.1", "8.8.8.8"]
        current.dns["CNAME"] = ["EDGE.EXAMPLE.COM.", "edge.example.com"]
        current.certificates[0].sans.reverse()
        next(s for s in current.services if s.port == 22).product = " open   SSH "
        assert compare(original, current) == []
        next(s for s in current.services if s.port == 80).state = "open"
        assert kinds(compare(original, current)) == ["NEW_PORT"]


@pytest.mark.parametrize(
    "failure",
    [
        dns.resolver.NXDOMAIN(),
        dns.resolver.NoNameservers(),
        dns.exception.Timeout(),
        dns.resolver.LifetimeTimeout(),
    ],
)
def test_dns_uncertainty_fails_before_any_probe(failure):
    with (
        patch("app.scanner.dns.dns.resolver.Resolver") as resolver,
        patch("app.scanner.pipeline.scan_address") as probe,
    ):
        resolver.return_value.resolve.side_effect = failure
        result = execute_scan("example.com", [443], get_settings())
    assert result.state == "FAILED" and not result.services
    probe.assert_not_called()


def test_mixed_dns_set_is_rejected_before_probe():
    with (
        patch("app.scanner.dns.dns.resolver.Resolver") as resolver,
        patch("app.scanner.pipeline.scan_address") as probe,
    ):
        resolver.return_value.resolve.side_effect = [["8.8.8.8", "127.0.0.1"], [], []]
        result = execute_scan("example.com", [80], get_settings())
    assert result.state == "FAILED"
    probe.assert_not_called()


def test_hex_like_hostname_still_uses_dns_and_endpoint_policy():
    # A syntactically valid DNS label is not fed to libc's permissive IP parser.
    host = normalize_target("0x7f.0.0.1")
    with (
        patch("app.scanner.dns.dns.resolver.Resolver") as resolver,
        patch("app.scanner.pipeline.scan_address") as probe,
    ):
        resolver.return_value.resolve.side_effect = [["127.0.0.1"], [], []]
        assert execute_scan(host, [80], get_settings()).state == "FAILED"
    resolver.return_value.resolve.assert_any_call(host, "A")
    probe.assert_not_called()


def test_resolution_pins_nmap_and_tls_once_with_original_sni():
    with (
        patch("app.scanner.dns.dns.resolver.Resolver") as resolver,
        patch("app.scanner.pipeline.scan_address") as probe,
        patch("app.scanner.pipeline.collect_certificate") as tls,
    ):
        resolver.return_value.resolve.side_effect = [["8.8.8.8"], ["2001:4860:4860::8888"], []]
        probe.side_effect = lambda ip, *_: [Service(address=ip, port=443, state="open")]
        tls.side_effect = lambda ip, port, host, _: cert(address=ip, port=port, hostname=host)
        result = execute_scan("example.com", [443], get_settings())
    assert result.state == "SUCCESS" and resolver.return_value.resolve.call_count == 3
    assert {call.args[0] for call in probe.call_args_list} == set(result.addresses)
    assert {call.args[0] for call in tls.call_args_list} == set(result.addresses)
    assert all(call.args[2] == "example.com" for call in tls.call_args_list)


def test_excessive_dns_addresses_never_truncated():
    with patch("app.scanner.dns.dns.resolver.Resolver") as resolver:
        resolver.return_value.resolve.side_effect = [["8.8.8.8", "8.8.4.4"], [], []]
        with pytest.raises(ValueError, match="limit"):
            resolve_target("example.com", "", max_addresses=1)


@pytest.mark.parametrize(
    "outcome",
    [
        FileNotFoundError(),
        PermissionError(),
        subprocess.TimeoutExpired(["nmap"], 1),
        "empty",
        "truncated",
        "signal",
        "exit",
    ],
)
def test_scanner_execution_failures_never_promote_or_remove(session_factory, outcome):
    with session_factory() as db:
        target = make_target(db)
        run(db, target)
        baseline = target.baseline_scan_id
        with (
            patch("app.scanner.pipeline.resolve_target", return_value=([target.host], {})),
            patch("app.scanner.nmap.subprocess.run") as process,
        ):
            if isinstance(outcome, Exception):
                process.side_effect = outcome
            else:
                process.return_value.returncode = {"signal": -9, "exit": 2}.get(outcome, 0)
                process.return_value.stdout = "" if outcome == "empty" else "<nmaprun>"
            result = execute_scan(target.host, [8000], get_settings())
        job = enqueue(db, target, [8000])
        job.state = "RUNNING"
        job.started_at = datetime.now(UTC)
        db.commit()
        events = finish_scan(db, job.id, result, get_settings())
        assert result.state == "FAILED" and target.baseline_scan_id == baseline
        assert [e.type for e in events] == ["SCAN_FAILED"]


@pytest.mark.parametrize(
    "seconds,expected",
    [
        (-1, "TLS_EXPIRED"),
        (0, "TLS_EXPIRED"),
        (1, "TLS_CRITICAL"),
        (7 * 86400, "TLS_CRITICAL"),
        (7 * 86400 + 1, "TLS_EXPIRING"),
        (14 * 86400, "TLS_EXPIRING"),
        (30 * 86400, "TLS_EXPIRING"),
        (30 * 86400 + 1, None),
    ],
)
def test_tls_exact_instant_and_timezone(seconds, expected):
    expiry = (NOW + timedelta(seconds=seconds)).astimezone(timezone(timedelta(hours=7)))
    events = compare(snapshot(), snapshot(certificates=[cert(not_after=expiry)]))
    assert kinds(events) == ([expected] if expected else [])


def test_malformed_der_rejected():
    with pytest.raises(ValueError):
        parse_certificate(b"not a certificate", "127.0.0.1", 443, "example.com")


def test_multiple_closures_reopen_and_uncertainty_do_not_leak_between_ports(session_factory):
    with session_factory() as db:
        target = make_target(db)

        def observe(states, state="SUCCESS"):
            job = enqueue(db, target, [22, 443])
            job.state = "RUNNING"
            job.started_at = datetime.now(UTC)
            db.commit()
            return finish_scan(
                db, job.id, snapshot(state, ports=(22, 443), states=states), get_settings()
            )

        observe(("open", "open"))
        assert observe(("closed", "open")) == []
        assert len(db.scalars(select(ChangeCandidate)).all()) == 1
        assert observe(("open", "open")) == []
        assert not db.scalars(select(ChangeCandidate)).all()
        assert observe(("closed", "open")) == []
        assert [e.details["port"] for e in observe(("closed", "open"))] == [22]
        baseline = target.baseline_scan_id
        assert "REMOVED_PORT" not in [e.type for e in observe(("closed", "filtered"), "PARTIAL")]
        assert target.baseline_scan_id == baseline
        assert observe(("closed", "closed")) == []
        assert [e.details["port"] for e in observe(("closed", "closed"))] == [443]


def test_all_owned_write_paths_and_history_reject_other_user(logged_in, session_factory):
    c = logged_in
    target = add_target(c).json()
    rule = c.post(
        "/api/notifications/rules", json={"channel": "smtp", "destination": "lab@example.test"}
    ).json()
    c.post(f"/api/targets/{target['id']}/scans")
    from app.worker import tick

    tick(session_factory, get_settings(), lambda *_: Snapshot(state="FAILED"))
    event = c.get("/api/events").json()[0]
    c.post("/api/auth/logout")
    c.post("/api/auth/login", json={"username": "other", "password": "another-test-password"})
    target_data = dict(name="owned", host="127.0.0.1", profile_id=1, authorized=True)
    rule_data = dict(channel="smtp", destination="other@example.test")
    for response in [
        c.put(f"/api/targets/{target['id']}", json=target_data),
        c.delete(f"/api/targets/{target['id']}"),
        c.post(f"/api/targets/{target['id']}/scans"),
        c.post(f"/api/events/{event['id']}/acknowledge"),
        c.put(f"/api/notifications/rules/{rule['id']}", json=rule_data),
        c.post(f"/api/notifications/rules/{rule['id']}/test"),
    ]:
        assert response.status_code == 404
    for path in ("targets", "scans", "events", "notifications", "notifications/rules"):
        assert c.get("/api/" + path).json() == []


@pytest.mark.parametrize("path", ["events", "scans", "notifications"])
def test_pagination_bounds(logged_in, path):
    for query in ("limit=0", "limit=201", "offset=-1"):
        assert logged_in.get(f"/api/{path}?{query}").status_code == 422
    assert logged_in.get(f"/api/{path}?offset=999999").json() == []


def test_scheduler_multiple_due_disabled_archived_and_interval(session_factory):
    with session_factory() as db:
        first = make_target(db)
        for index, flags in enumerate(({}, {"enabled": False}, {"archived": True}), start=2):
            db.add(
                Target(
                    owner_id=1,
                    name=f"target {index}",
                    host=f"127.0.0.{index}",
                    profile_id=1,
                    authorized=True,
                    interval_seconds=600,
                    next_scan_at=datetime.now(UTC) - timedelta(hours=2),
                    **flags,
                )
            )
        first.next_scan_at = datetime.now(UTC) - timedelta(hours=2)
        first.interval_seconds = 900
        db.commit()
        before = datetime.now(UTC)
        schedule_due(db)
        schedule_due(db)
        from app.db.models import Scan

        assert {s.target_id for s in db.scalars(select(Scan))} == {first.id, first.id + 1}
        next_at = (
            first.next_scan_at.replace(tzinfo=UTC)
            if first.next_scan_at.tzinfo is None
            else first.next_scan_at
        )
        assert 899 <= (next_at - before).total_seconds() <= 905
        assert enqueue(db, first, [22]) is None
