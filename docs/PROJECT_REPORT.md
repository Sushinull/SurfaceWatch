# SurfaceWatch V1 project report

Date: 2026-10-06. Repository: [Sushinull/SurfaceWatch](https://github.com/Sushinull/SurfaceWatch), private, branch `main`.

## Implemented

The initially empty repository now contains a complete local monitoring application:
FastAPI authentication and ownership-checked APIs; bounded Nmap TCP/service scanning;
normalized DNS and direct TLS observations; immutable snapshots; a separate diff
engine; repeated closure confirmation; PostgreSQL models/migrations; durable manual
and scheduled jobs; a serial worker; notification rules/outbox/retries; responsive
React views; non-root application containers; an isolated HTTP/TLS/SMTP demo;
configuration generation; tests; and operator/developer documentation.

The required event vocabulary is supported: INITIAL_BASELINE, NEW_PORT,
REMOVED_PORT, SERVICE_CHANGED, PORT_STATE_CHANGED, IP_CHANGED, DNS_CHANGED,
TLS_RENEWED, TLS_CHANGED, TLS_EXPIRING, TLS_CRITICAL, TLS_EXPIRED,
TLS_HOSTNAME_MISMATCH, HOST_DOWN, SCAN_FAILED and SCAN_PARTIAL. HOST_DOWN is
reserved for independent confirmed evidence; no timeout is labeled host down.

## Architecture

React/TypeScript/Vite → same-origin Nginx proxy → FastAPI → PostgreSQL. A separate
Python worker owns scheduling, scanning, comparison and notification delivery.
PostgreSQL stores durable jobs and history; no Redis/Celery/cloud service is needed.
The scanner and diff engine are independent of HTTP and UI code. A future queue
adapter can preserve those modules. See ARCHITECTURE.md for tables and lifecycle.

A SUCCESS observation can advance the trusted baseline. PARTIAL/FAILED cannot.
REMOVED_PORT requires explicit closed states across two consecutive complete
observations by default; interruptions reset confirmation. DNS record ordering and
metadata-only formatting differences do not produce changes. Scope/host changes
establish a new baseline while preserving history.

## Verification actually executed

| Check | Result / evidence |
|---|---|
| Local complete suite, including real Nmap/TLS/SMTP | **70 passed**, 34.76 s |
| Same complete suite against native PostgreSQL 17 | **70 passed**, 37.92 s, GitHub Actions |
| Native PostgreSQL Alembic upgrade + schema consistency | **PASS**, no new upgrade operations |
| Python Ruff lint and formatting | **PASS** locally and on CI |
| TypeScript check + Vite production build | **PASS** locally and on CI |
| Prettier source formatting | **PASS** on CI |
| Compose configuration, image builds, startup and proxied API health | **PASS** on GitHub Actions |
| Browser smoke, actual FastAPI/worker/Nmap/TLS/SMTP | **PASS**: login, target/custom profile, scan, snapshot, event filter, SMTP test, desktop and 390 px mobile |
| Backend requirements dependency audit | **No known vulnerabilities reported** after cryptography update |
| Frontend production dependency audit | **No known vulnerabilities reported** |

CI evidence: [SurfaceWatch checks run 1](https://github.com/Sushinull/SurfaceWatch/actions/runs/37451658984), source commit `96a13621bdf44f2b28820dff1f057133f0994e23`. All three jobs (backend/frontend/docker) passed. The only test warning was a Starlette test-client deprecation concerning HTTPX; it did not affect behavior.

The live Nmap scenario opens temporary local HTTP services, establishes a baseline,
repeats an equivalent scan with no false event, starts a new service, detects
NEW_PORT, stops it, verifies the first closure remains a candidate, detects
REMOVED_PORT on the next complete scan, then injects a controlled failure and
proves SCAN_FAILED with no fake removal and unchanged baseline. A real local TLS
handshake collects a six-day certificate and detects TLS_CRITICAL. A real local
SMTP receiver accepts a notification. Fixture tests cover all expiry bands,
certificate replacement, hostname matching, DNS changes/reordering, malformed XML,
validation, ownership, CSRF, queue overlap, history and delivery retries.

A real headless Chromium browser also exercised the React app with an actual local API and worker (SQLite test storage), real Nmap, a six-day TLS certificate, and a local SMTP receiver. It verified login, target/custom-profile creation, live baseline, TLS warning, target detail, snapshot inspection, severity filtering, test delivery, no JavaScript errors and no document overflow at 390 px. The captured dashboard is in `docs/dashboard.png`.

The local execution host has no Docker daemon or native PostgreSQL server. The
native PostgreSQL and Docker checks were therefore run on GitHub Actions instead.
An embedded PostgreSQL experiment validated migration generation but was not
counted as full database verification; the native CI result is authoritative.

## Security

Implemented controls include Argon2 password hashes, HMAC-hashed opaque expiring
sessions, HttpOnly/SameSite cookies, login throttling, exact-origin/header CSRF checks,
user ownership checks, input limits, safe subprocess arrays, pinned DNS/IP policy,
private CIDR gates, defusedxml, parameterized ORM queries, React escaping, Nginx CSP,
secret-free browser configuration and sanitized notification/request logging.
HTTP client request logging is suppressed because Telegram request URLs contain
the bot token. No real secrets are committed. Dependency audits prompted an update
of cryptography to the checked version before final verification.

## Known V1 limitations

- Trusted local operators only; no public multi-tenant deployment or scan ownership proof.
- One serial worker. Multi-IP targets can delay the queue; deadlines are per IP.
- Direct TLS only; no STARTTLS, chain/revocation validation or certificate trust claims.
- TLS/filtered uncertainty holds the whole baseline; successful target evidence may lag.
- CDN/geographic DNS variation can be legitimate; missing address scope is not port closure.
- Conservative version comparisons skip missing/enriched unreliable metadata.
- Notification delivery is at least once; interruption after sending can duplicate a message.
- History has no automatic retention purge or cryptographic tamper-proofing.
- No vulnerability scanning, CVE correlation, UDP, exploitation or subnet discovery.
- Point-in-time audits are not a guarantee against future vulnerabilities.

## Exact clean-clone run instructions

```bash
git clone https://github.com/Sushinull/SurfaceWatch.git
cd SurfaceWatch
python scripts/setup.py
docker compose up --build -d
docker compose exec backend python -m app.cli create-user --username admin
```

Open http://localhost:8080. Choose a strong local password. Add an authorized host,
select its profile and run a scan. For the full demo, use:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml up --build -d
```

Add `172.30.0.10` with custom ports `8000,8081,8443`. Follow DEMO.md to toggle
EXTRA_SERVICE, scan twice for closure, test certificate expiry and inspect free
SMTP delivery in Mailpit at http://localhost:8025. README.md contains native
development, migrations, password reset, configuration, tests and backup commands.

## Repository status

Changes are organized into logical core, backend, frontend/deployment, verification
and documentation commits. The final documentation commit descends from the tested
source commit above. The published `main` source tree is compared against the local
committed tree during delivery. Repository visibility remains private.

## V2 roadmap

1. Endpoint-level trust so one TLS failure need not hold unrelated TCP observations.
2. Durable parallel claims/leases and separate delivery workers for larger deployments.
3. Per-target explicit IP allowlists, audit log and safer remote deployment controls.
4. Certificate-chain verification, STARTTLS and configurable per-target SNI/TLS policy.
5. Baseline approval, longer confirmation windows and maintenance/suppression schedules.
6. Incremental server-side pagination, retention/export and signed evidence bundles.
7. Optional authorized subdomain inventory/CVE enrichment, keeping change monitoring separate.

V2 features do not block the delivered local V1.
