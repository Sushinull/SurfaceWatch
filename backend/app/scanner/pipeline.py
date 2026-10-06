import logging

from app.core.config import Settings
from app.scanner.dns import resolve_target
from app.scanner.nmap import scan_address
from app.scanner.tls import collect_certificate
from app.scanner.types import ScanState, Snapshot

log = logging.getLogger(__name__)
TLS_PORTS = {443, 465, 636, 853, 993, 995, 8443, 9443}


def execute_scan(host: str, ports: list[int], settings: Settings) -> Snapshot:
    result = Snapshot(state=ScanState.RUNNING, ports=sorted(ports))
    try:
        result.addresses, result.dns = resolve_target(
            host, settings.allowed_target_cidrs, settings.max_target_addresses
        )
    except Exception as exc:
        result.state = ScanState.FAILED
        result.errors.append(str(exc))
        return result
    completed = 0
    for address in result.addresses:
        try:
            services = scan_address(address, ports, settings.scan_timeout)
            result.services.extend(services)
            completed += 1
        except Exception as exc:
            result.errors.append(f"{address}: TCP scan {type(exc).__name__}: {exc}")
            continue
        if any(s.state not in {"open", "closed"} for s in services):
            result.errors.append(f"{address}: filtered/uncertain port states; baseline retained")
        for svc in services:
            if svc.state != "open" or not (svc.tunnel == "ssl" or svc.port in TLS_PORTS):
                continue
            try:
                result.certificates.append(
                    collect_certificate(address, svc.port, host, settings.tls_timeout)
                )
            except Exception as exc:
                result.errors.append(f"{address}:{svc.port}: TLS collection {type(exc).__name__}")
    result.state = (
        ScanState.FAILED
        if not completed
        else (ScanState.PARTIAL if result.errors else ScanState.SUCCESS)
    )
    return result
