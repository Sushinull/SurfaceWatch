# SurfaceWatch V1 final audit and freeze report

This preserves historical v1.0.0 verification. Current main also contains the
subsequent [v1.0.1 hardening report](HARDENING_REPORT.md); use it and the patch
release's exact-SHA CI evidence for current source. The old tag remains immutable.

Date: 2026-10-06. Repository: [Sushinull/SurfaceWatch](https://github.com/Sushinull/SurfaceWatch), private, branch `main`.
Scope: authorized local portfolio and small-lab monitoring. This is not a claim of
production readiness or public multi-tenant deployment.

## Audit and source provenance

The actual GitHub main head at audit start was
`f88bfb4bef163aa483230529d19d3c4a483a543c`. Its source tree matched the clean local
checkout. Changes preserve the scanner, data model, migrations and UI design.
Reviewed: APIs/auth/CSRF/ownership, schema and migration consistency, scanner argv
and XML coverage, DNS/IP pinning, direct TLS, comparison/confirmation/deduplication,
worker/recovery/scheduler/outbox, logging/secrets, Docker/demo networking, frontend
states/filters/snapshots/mobile behavior, dependencies, CI and documentation.

## Issues fixed

| Issue | Root cause | Fix and evidence |
|---|---|---|
| A: Mailpit port 8025 configured but unreachable on the reported Windows Docker setup | Mailpit joined only an internal lab network. The operator reproduced restored access by attaching the normal default network. | `docker-compose.demo.yml` attaches Mailpit to `lab` and `default`. Only `127.0.0.1:8025` is published; SMTP 1025 and lab services remain unpublished. Static regression checks isolation/network membership. Effective Compose and real host HTTP/SMTP are checked by CI. |
| B: SMTP NOT CONFIGURED despite successful delivery | `/notifications/config` reads backend settings, but the demo originally set SMTP only on worker. | One YAML anchor gives backend and worker the same demo SMTP settings, with empty SMTP credentials. Regression checks API booleans and secret redaction; Docker and browser tests verify CONFIGURED plus SENT/received evidence. Telegram/Discord status remains based on their own environment settings. |
| IPv4-mapped IPv6 bypass of hard endpoint denial | The denial compared the metadata IPv4 string without inspecting a mapped IPv4 endpoint. | `backend/app/core/validation.py` checks the underlying mapped endpoint. Three regression cases reject mapped metadata, unspecified and multicast endpoints even with `::/0`. |
| CI expression context | The initial expanded workflow put `runner.temp` in job-level env, which GitHub does not allow. | A disposable runner-local credential file path replaces that expression. Actionlint and the subsequent complete CI run passed. No tag was created from the failed workflow. |

No new product features, schema changes, paid integrations or UI redesign were added.

## Verification actually executed

Pre-freeze source: `8ed4b14f8e3229cfd66c0f3f2bd9f2db541af321`.
[Complete CI evidence](https://github.com/Sushinull/SurfaceWatch/actions/runs/37487298131):
backend, frontend and docker all **success**.

| Check | Actual result |
|---|---|
| Standard local backend fixture suite | **75 passed, 3 live tests skipped**, 4.40 s |
| Complete local suite with real Nmap/TLS/SMTP | **78 passed**, 36.20 s |
| Complete native PostgreSQL 17 CI suite, including live integrations | **78 passed**, 42.99 s |
| PostgreSQL Alembic upgrade + schema consistency | **PASS**, no new upgrade operations |
| Ruff lint and formatting | **PASS**, local and CI |
| Actionlint on CI/release workflows | **PASS**, local |
| Frontend npm ci, TypeScript, Vite build, Prettier | **PASS**, local and CI |
| Backend production requirements audit | **No known vulnerabilities reported**, local and CI |
| Frontend dependency audit, including development dependencies | **0 vulnerabilities**, local and CI |
| Effective Compose, image builds, startup, proxied health | **PASS**, CI |
| Actual Mailpit port and host UI, SMTP message receipt | **PASS**, CI |
| Real worker SIGKILL/restart recovery | **PASS**, CI: FAILED + SCAN_FAILED, unchanged baseline, no fake removal |
| Real scheduler consuming a persisted due timestamp | **PASS**, CI, source scheduled and no overlapping active job |
| Browser UI on Docker/PostgreSQL deployment | **PASS**, CI: login, channel badges, SMTP test, details, immutable snapshot, severity filter, history, 390 px mobile, no JS errors |
| Browser UI on native local services | **PASS**, actual API/worker/Nmap/TLS/SMTP, SQLite test storage, Chromium 143 |

CI Docker runner: Linux, Engine **28.0.4**, Compose **2.38.2**. This is independent
of the operator's Windows Engine 29.8.1 / Compose 5.5.1 evidence; the latter was not
rerun on this execution host. Local Nmap: 7.94SVN. CI browser: Chrome 151 through
locked Playwright 1.62.1. One Starlette/HTTPX test-client deprecation warning remains;
GitHub action runtime/cache warnings did not fail checks. No test failures remain.

The local host has no Docker daemon or native PostgreSQL server. Those checks ran
on GitHub Actions. The release's **final exact SHA** is tested again after this
report/docs commit. The release gate requires all mandatory jobs on that SHA and
checks it is still main's HEAD. The GitHub Release records the final SHA and CI URL;
it does not rely only on the pre-freeze CI run above.

## Acceptance evidence

| Scenario | Independently executed in this audit | Operator-provided Windows acceptance |
|---|---|---|
| Baseline: 8000/8443 open, 8081 closed | PASS, Docker | PASS |
| Equivalent repeated scan, no false/duplicate change | PASS, local Nmap and Docker | PASS |
| Extra service: NEW_PORT 8081 | PASS, Docker | PASS |
| Removal: first candidate, second complete scan REMOVED_PORT | PASS, local Nmap and Docker | PASS |
| Recreated TLS certificate: renewal/change | PASS, Docker; fixtures cover both classifications | PASS |
| Six-day TLS certificate: TLS_CRITICAL/HIGH | PASS, real TLS and Docker | PASS |
| Worker SIGKILL/restart: failure and preserved baseline | PASS, actual Docker worker kill/restart | PASS |
| SMTP test: SENT and Mailpit receipt | PASS, sender/recipient/subject/body and UI badge | PASS after manual network workaround |
| Scheduled scan | PASS, persisted due timestamp advanced only on disposable CI target | PASS after normal five-minute interval |

Fixture regressions also prove FAILED/PARTIAL never promote baselines or imply
removal, both reset pending closure counts, completed snapshots cannot be replaced,
repeated conditions are deduplicated, queue overlap is rejected, history survives
archive, event filtering/acknowledgment respects ownership, retry three is terminal,
and disabled rules cancel pending messages. SMTP is verified end to end; real
Telegram/Discord provider delivery was not attempted without operator credentials.

## Security review

Argon2 account hashes; expiring opaque HttpOnly/SameSite sessions stored as HMAC
hashes; login throttling; exact-origin/header CSRF checks; ownership on data routes;
parameterized ORM access; bounded validated inputs; React text escaping and Nginx
CSP; fixed Nmap argv without shell execution; resolve-once pinned-IP policy;
explicit private CIDR gates and hard endpoint denials; defusedxml; secret-free
channel configuration and sanitized notification/request logging remain in place.

Published UI/database/Mailpit ports bind only to loopback. The HTTP/TLS lab remains
internal without published ports. Application containers run without root or added
capabilities. Demo plaintext SMTP stays a deliberate local-only exception. No real
credentials/private-key literals, `.env`, database files, dependency directories or
build outputs are tracked. Audits are point-in-time results, not future guarantees.

## Known V1 limitations

- Trusted local operators only; authorization acknowledgment is not proof of ownership.
- One serial worker; slow/multi-IP targets delay the queue, with deadlines per IP.
- Direct TLS only; no STARTTLS, chain/revocation validation or trust assertion.
- TLS/filtered uncertainty holds the whole baseline; trusted evidence may lag.
- CDN/geographic DNS changes can be legitimate; disappeared IP scope is not closure.
- Conservative service/version comparisons skip missing or unreliable metadata.
- At-least-once notification delivery may duplicate after external acceptance/crash.
- No automatic history retention, signed evidence ledger or vulnerability detection.
- Dashboard TLS alert count represents unacknowledged warning events; inspect the
  current trusted certificate and acknowledge historical alerts after review.
- Source is frozen; backend transitive dependencies and image tags resolve at build
  time. Changes to dependencies/platforms still need deliberate regression checks.

## Repository hygiene and release gate

Source, regression scripts, documentation and workflow files are committed to main.
Generated secrets, temporary databases, node_modules, dist and test caches are
ignored. Local documentation links and whitespace were checked. The GitHub tree is
compared with the locally committed tree before delivery. No user volume was reset;
CI cleanup removes only the fresh `surfacewatch-regression` project's volumes.

The one-time release workflow accepts only a successful main push whose exact
message is `release: freeze SurfaceWatch v1.0.0`. It verifies the current main SHA
and all backend/frontend/docker job conclusions, refuses an existing tag, creates
an annotated `v1.0.0` on the tested SHA and publishes **SurfaceWatch v1.0.0** with
that SHA/CI evidence. Product behavior stays within V1 scope.

## Exact clean-clone run instructions

```bash
git clone https://github.com/Sushinull/SurfaceWatch.git
cd SurfaceWatch
git checkout v1.0.0
python scripts/setup.py
docker compose up --build -d
docker compose exec backend python -m app.cli create-user --username admin
```

Open http://localhost:8080. Choose a strong password. Add an authorized host/profile
and run a scan. Existing `.env` is preserved; changing POSTGRES_PASSWORD does not
change an initialized database role. `down` preserves history; `down -v` deletes it.

## Short local demo

Use both Compose files instead of the base-only startup:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml up --build -d
```

Create the admin once. Add `172.30.0.10`, custom ports `8000,8081,8443`, and scan.
Add SMTP `demo@example.test` with minimum LOW; Send test and inspect
http://localhost:8025. SMTP should say CONFIGURED. Follow DEMO.md for service toggle,
two-scan closure, certificate expiry and abrupt recovery, including PowerShell
syntax. Do not run the disposable CI acceptance script against your installation.

## V2 roadmap

1. Endpoint-level trust so one TLS failure need not hold unrelated TCP observations.
2. Durable parallel claims/leases and separate delivery workers for larger deployments.
3. Per-target explicit IP allowlists, audit log and safer remote deployment controls.
4. Certificate-chain verification, STARTTLS and configurable per-target SNI/TLS policy.
5. Baseline approval, longer confirmation windows and maintenance/suppression schedules.
6. Incremental server-side pagination, retention/export and signed evidence bundles.
7. Optional authorized subdomain inventory/CVE enrichment, keeping change monitoring separate.

V2 features do not block the delivered local V1.
