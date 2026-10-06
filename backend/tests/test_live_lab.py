"""Live local-only integrations. Set RUN_LIVE_LAB=1; never scans public hosts."""

import os
import shutil
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from aiosmtpd.controller import Controller
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.core.config import get_settings
from app.scanner.pipeline import execute_scan
from app.scanner.tls import collect_certificate
from app.services.notifications import send_notification
from app.services.scans import enqueue, finish_scan
from tests.test_persistence import make_target

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_LIVE_LAB") != "1", reason="Opt-in local live integration"
)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Authorized local lab")

    def log_message(self, *args):
        pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve(port):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_live_nmap_baseline_add_remove_failure(session_factory):
    assert shutil.which("nmap"), "Install Nmap for RUN_LIVE_LAB=1"
    first, second = free_port(), free_port()
    server = serve(first)
    extra = None
    settings = get_settings().model_copy(
        update={"allowed_target_cidrs": "127.0.0.0/8", "scan_timeout": 30}
    )
    with session_factory() as db:
        target = make_target(db)

        def run():
            job = enqueue(db, target, [first, second])
            db.commit()
            job.state = "RUNNING"
            job.started_at = datetime.now(UTC)
            db.commit()
            snapshot = execute_scan("127.0.0.1", [first, second], settings)
            assert snapshot.state == "SUCCESS", snapshot.errors
            return job, finish_scan(db, job.id, snapshot, settings)

        try:
            assert [e.type for e in run()[1]] == ["INITIAL_BASELINE"]
            assert not run()[1]
            extra = serve(second)
            assert "NEW_PORT" in [e.type for e in run()[1]]
            extra.shutdown()
            extra.server_close()
            extra = None
            assert not run()[1]
            assert [e.type for e in run()[1]] == ["REMOVED_PORT"]
            baseline = target.baseline_scan_id
            from app.scanner.types import Snapshot

            job = enqueue(db, target, [first, second])
            db.commit()
            job.state = "RUNNING"
            job.started_at = datetime.now(UTC)
            db.commit()
            events = finish_scan(
                db, job.id, Snapshot(state="FAILED", errors=["controlled failure"]), settings
            )
            assert [e.type for e in events] == [
                "SCAN_FAILED"
            ] and target.baseline_scan_id == baseline
        finally:
            server.shutdown()
            server.server_close()
            if extra:
                extra.shutdown()
                extra.server_close()


def test_live_tls_expiring_collection(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=6))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .sign(key, hashes.SHA256())
    )
    (tmp_path / "key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (tmp_path / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tmp_path / "cert.pem", tmp_path / "key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        collected = collect_certificate("127.0.0.1", server.server_port, "localhost", 5)
        assert (
            collected.hostname_matches
            and collected.serial == "1"
            and len(collected.fingerprint) == 64
        )
        from app.diff.engine import compare
        from app.scanner.types import Snapshot

        assert "TLS_CRITICAL" in [
            e.type for e in compare(None, Snapshot(state="SUCCESS", certificates=[collected]))
        ]
    finally:
        server.shutdown()
        server.server_close()


def test_live_free_smtp_delivery():
    messages = []

    class Receiver:
        async def handle_DATA(self, server, session, envelope):
            messages.append(envelope.content.decode())
            return "250 accepted"

    port = free_port()
    controller = Controller(Receiver(), hostname="127.0.0.1", port=port)
    controller.start()
    try:
        settings = get_settings().model_copy(
            update={
                "smtp_host": "127.0.0.1",
                "smtp_port": port,
                "smtp_starttls": False,
                "smtp_allow_plaintext": True,
            }
        )
        send_notification(
            "smtp", "lab@example.com", "SurfaceWatch controlled live delivery", settings
        )
        assert len(messages) == 1 and "SurfaceWatch controlled live delivery" in messages[0]
    finally:
        controller.stop()
