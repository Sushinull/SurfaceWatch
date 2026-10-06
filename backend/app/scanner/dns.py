import ipaddress

import dns.exception
import dns.resolver

from app.core.validation import address_allowed


def resolve_target(host: str, cidrs: str, max_addresses: int = 8) -> tuple[list[str], dict]:
    try:
        addresses = [str(ipaddress.ip_address(host))]
        records = {}
    except ValueError:
        records = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 6
        for kind in ("A", "AAAA", "CNAME"):
            try:
                answer = resolver.resolve(host, kind)
                records[kind] = sorted({str(r).lower().rstrip(".") for r in answer})
            except dns.resolver.NoAnswer:
                records[kind] = []
            except dns.exception.DNSException:
                raise ValueError("DNS resolution failed or was incomplete") from None
        addresses = sorted(set(records["A"] + records["AAAA"]))
    if not addresses:
        raise ValueError("DNS returned no addresses")
    if len(addresses) > max_addresses:
        raise ValueError("Address count exceeds configured limit; select explicit IP targets")
    if any(not address_allowed(ip, cidrs) for ip in addresses):
        raise ValueError("Target resolves outside permitted address ranges")
    return addresses, records
