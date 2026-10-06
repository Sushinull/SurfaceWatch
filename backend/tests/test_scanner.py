from pathlib import Path
from unittest.mock import patch
from xml.etree.ElementTree import ParseError

import pytest
from defusedxml.common import DefusedXmlException

from app.core.validation import address_allowed, normalize_target
from app.scanner.nmap import parse_xml, scan_address
from app.scanner.tls import hostname_matches

XML = (Path(__file__).parent / "fixtures/nmap.xml").read_text()


def test_parser_expands_closed_only_with_exact_coverage():
    services = parse_xml(XML, "127.0.0.1", [22, 80])
    assert [(s.port, s.state) for s in services] == [(22, "open"), (80, "closed")]
    with pytest.raises(ValueError):
        parse_xml(XML, "127.0.0.1", [22, 80, 443])


@pytest.mark.parametrize(
    "xml",
    [
        "<bad",
        XML.replace('exit="success"', 'exit="error"'),
        XML.replace('state="up"', 'state="down"'),
        XML.replace("127.0.0.1", "127.0.0.2"),
        XML.replace("<host>", '<host timedout="true">'),
        '<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>',
    ],
)
def test_parser_rejects_uncertain_or_unsafe(xml):
    with pytest.raises((ValueError, ParseError, DefusedXmlException)):
        parse_xml(xml, "127.0.0.1", [22, 80])


@pytest.mark.parametrize(
    "target",
    [
        ";whoami",
        "-sV",
        "example.com;id",
        "http://example.com",
        "a/b",
        "127.0.0.1/24",
        "*.example.com",
        "x\nlocalhost",
        "[::1]",
        "fe80::1%eth0",
        "999.999.999.999",
        "x$(id).com",
        "x`id`.com",
        "",
    ],
)
def test_bad_targets(target):
    with pytest.raises(ValueError):
        normalize_target(target)


@pytest.mark.parametrize(
    "target,expected",
    [
        ("EXAMPLE.com.", "example.com"),
        ("127.0.0.1", "127.0.0.1"),
        ("2001:db8::1", "2001:db8::1"),
        ("lab", "lab"),
    ],
)
def test_normalization(target, expected):
    assert normalize_target(target) == expected


def test_address_policy():
    assert not address_allowed("127.0.0.1", "")
    assert address_allowed("127.0.0.1", "127.0.0.0/8")
    assert not address_allowed("169.254.169.254", "0.0.0.0/0")
    assert not address_allowed("224.0.0.1", "0.0.0.0/0")


def test_subprocess_argument_array_and_pinned_ip():
    with patch("app.scanner.nmap.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = XML
        scan_address("127.0.0.1", [22, 80], 30)
        args = run.call_args.args[0]
        assert isinstance(args, list) and args[-1] == "127.0.0.1" and "-sT" in args
        assert "shell" not in run.call_args.kwargs


def test_hostname_wildcard_boundary():
    assert hostname_matches("a.example.com", ["*.example.com"])
    assert not hostname_matches("a.b.example.com", ["*.example.com"])
    assert not hostname_matches("example.com", ["*.example.com"])
    assert hostname_matches("127.0.0.1", ["127.0.0.1"])
