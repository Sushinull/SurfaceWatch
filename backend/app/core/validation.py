import ipaddress
import re


def normalize_target(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 253 or any(c in value for c in "/\\%@:#?[]"):
        # IPv6 literals contain colons, but never a URL, zone ID or brackets.
        try:
            if "%" in value:
                raise ValueError
            return str(ipaddress.ip_address(value))
        except ValueError:
            raise ValueError(
                "Use a domain or one IPv4/IPv6 address, without URL, CIDR or flags"
            ) from None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    value = value.rstrip(".").encode("idna").decode("ascii").lower()
    labels = value.split(".")
    if (
        len(value) > 253
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
        or value.replace(".", "").isdigit()
    ):
        raise ValueError("Invalid domain name")
    return value


def validate_ports(ports: list[int]) -> list[int]:
    if not ports or len(set(ports)) > 1024 or any(p < 1 or p > 65535 for p in ports):
        raise ValueError("Choose 1–1024 TCP ports between 1 and 65535")
    return sorted(set(ports))


def address_allowed(address: str, cidrs: str) -> bool:
    ip = ipaddress.ip_address(address)
    endpoint = ip.ipv4_mapped or ip if isinstance(ip, ipaddress.IPv6Address) else ip
    # Never probe unspecified, multicast or the common metadata endpoint.
    if endpoint.is_unspecified or endpoint.is_multicast or str(endpoint) == "169.254.169.254":
        return False
    networks = [ipaddress.ip_network(n.strip()) for n in cidrs.split(",") if n.strip()]
    if any(ip.version == n.version and ip in n for n in networks):
        return True
    return ip.is_global
