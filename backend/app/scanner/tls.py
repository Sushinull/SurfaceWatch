import hashlib
import ipaddress
import socket
import ssl

from cryptography import x509
from cryptography.x509.oid import NameOID

from app.scanner.types import Certificate


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
        return any(n == str(ip) for n in names)
    except ValueError:
        pass
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and host.endswith(name[1:]) and host.count(".") == name.count("."):
            return True
    return False


def parse_certificate(der: bytes, address: str, port: int, hostname: str) -> Certificate:
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName) + [
            str(i) for i in san.get_values_for_type(x509.IPAddress)
        ]
    except x509.ExtensionNotFound:
        # Legacy CN fallback for display/mismatch monitoring; not browser trust.
        names = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    return Certificate(
        address=address,
        port=port,
        hostname=hostname,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial=str(cert.serial_number),
        fingerprint=hashlib.sha256(der).hexdigest(),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        sans=sorted(set(names)),
        hostname_matches=hostname_matches(hostname, names),
    )


def collect_certificate(address: str, port: int, hostname: str, timeout: int) -> Certificate:
    # Verification is deliberately disabled ONLY for certificate observation so expired
    # and self-signed certificates can be inspected. No application data or credentials.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((address, port), timeout=timeout) as conn:
        with context.wrap_socket(conn, server_hostname=hostname) as tls:
            return parse_certificate(tls.getpeercert(binary_form=True), address, port, hostname)
