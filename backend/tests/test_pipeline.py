from unittest.mock import patch

from app.core.config import get_settings
from app.scanner.pipeline import execute_scan
from app.scanner.types import Service


def test_dns_failure_never_calls_nmap():
    with (
        patch("app.scanner.pipeline.resolve_target", side_effect=ValueError("DNS timeout")),
        patch("app.scanner.pipeline.scan_address") as scan,
    ):
        result = execute_scan("example.com", [443], get_settings())
    assert result.state == "FAILED" and not result.services
    scan.assert_not_called()


def test_tls_failure_is_partial_not_fatal():
    with (
        patch("app.scanner.pipeline.resolve_target", return_value=(["127.0.0.1"], {})),
        patch(
            "app.scanner.pipeline.scan_address",
            return_value=[Service(address="127.0.0.1", port=443, state="open", tunnel="ssl")],
        ),
        patch("app.scanner.pipeline.collect_certificate", side_effect=TimeoutError),
    ):
        result = execute_scan("example.com", [443], get_settings())
    assert result.state == "PARTIAL" and len(result.services) == 1


def test_denied_private_address_fails_before_scan():
    with patch("app.scanner.pipeline.scan_address") as scan:
        result = execute_scan(
            "127.0.0.1", [80], get_settings().model_copy(update={"allowed_target_cidrs": ""})
        )
    assert result.state == "FAILED"
    scan.assert_not_called()


def test_one_address_failure_retains_partial_data():
    with (
        patch("app.scanner.pipeline.resolve_target", return_value=(["127.0.0.1", "127.0.0.2"], {})),
        patch(
            "app.scanner.pipeline.scan_address",
            side_effect=[[Service(address="127.0.0.1", port=80, state="open")], TimeoutError],
        ),
    ):
        result = execute_scan("example.com", [80], get_settings())
    assert result.state == "PARTIAL" and len(result.services) == 1
