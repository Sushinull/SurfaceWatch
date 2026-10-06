"""Controlled HTTP/TLS lab. No host ports are published by Compose."""

import os
import signal
import ssl
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class Handler(BaseHTTPRequestHandler):
    server_version = "SurfaceWatchLab/1.0"

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"SurfaceWatch authorized demo service\n")

    def log_message(self, *args):
        pass


def certificate():
    import ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=int(os.getenv("CERT_DAYS", "90"))))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("lab"),
                    x509.IPAddress(ipaddress.ip_address("172.30.0.10")),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    Path("/tmp/lab.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    Path("/tmp/lab.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def main():
    certificate()
    servers = []
    for port in [int(os.getenv("HTTP_PORT", "8000")), 8443] + (
        [8081] if os.getenv("EXTRA_SERVICE", "false") == "true" else []
    ):
        server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        if port == 8443:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain("/tmp/lab.crt", "/tmp/lab.key")
            server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    print("Lab ready", flush=True)
    stopped = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopped.set())
    stopped.wait()
    for server in servers:
        server.shutdown()


if __name__ == "__main__":
    main()
