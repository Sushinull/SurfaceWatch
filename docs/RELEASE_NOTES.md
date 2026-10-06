# SurfaceWatch v1.0.1

Backward-compatible hardening of authorized local V1 monitoring. Thirteen confirmed
bugs fixed; no new providers, architecture, schema or UI redesign.

- Reject late/stale scan completion; recover orphaned RUNNING work after transient
  completion errors without promoting uncertain evidence.
- Keep TLS/change warning deduplication through FAILED/PARTIAL; attention status
  considers older unacknowledged significant events.
- Omit rejected secrets from API/settings validation and Uvicorn exception logging.
- Reject blank profile names; serialize notification rule count/insert on PostgreSQL.
- Reject obsolete UI refresh responses, honor configured TLS bands and restore
  mobile Sign out access.
- Clear account caches on authentication boundaries; reject late previous-owner
  snapshot/action results and stale whoami responses during account switching.
- Add deterministic adversarial/provider tests, real PG races and fresh Docker/SMTP,
  scheduler, recovery, DB/API outage and browser regression gates.

See [hardening report](https://github.com/Sushinull/SurfaceWatch/blob/main/docs/HARDENING_REPORT.md)
for reproduction, severity, coverage and honest platform limits. Windows Engine
29.8.1 / Compose 5.5.1 was not independently rerun; Linux verifies the unchanged
loopback/internal networking. Whole-baseline holding can omit rapid overlapping
reversals; delivery remains at least once. This is not public production readiness.

Upgrade: preserve `.env` and PostgreSQL volume, checkout v1.0.1, then rebuild/recreate
using your normal Compose files. `down` preserves history; `down -v` deletes it.
The annotated patch tag and Release require green CI on the exact final main SHA.
The v1.0.0 annotated tag remains immutable.

## Historical v1.0.0

SurfaceWatch V1 was frozen for authorized local portfolio and small-lab monitoring.

- Mailpit uses the internal lab and normal default bridge; its inspection UI stays
  bound to `127.0.0.1:8025`. Lab services and SMTP port 1025 are not host-published.
- Demo SMTP settings are shared by API and worker, so SMTP CONFIGURED agrees with
  actual delivery. Channel configuration responses contain only booleans.
- IPv4-mapped IPv6 cannot bypass hard denials for metadata, multicast or unspecified
  IPv4 endpoints, even with an explicit broad IPv6 CIDR.
- Regression checks cover immutable baselines, two-success closure confirmation,
  failed/partial interruption, native PostgreSQL migrations, real Nmap/TLS/SMTP,
  Docker Mailpit delivery, SIGKILL recovery, scheduling and the browser UI.

The annotated tag is created only after the exact main source SHA passes all three
mandatory CI jobs. This release is not a production/public multi-tenant deployment.

Known limits: one serial worker; direct TLS only; certificate chain trust is not
assessed; uncertain evidence holds the whole baseline; notification delivery is at
least once; history has no automatic retention or signed evidence ledger. V2 work
is listed separately in `docs/PROJECT_REPORT.md`.

Clean clone: generate `.env` with `python scripts/setup.py`, then
`docker compose up --build -d` and
`docker compose exec backend python -m app.cli create-user --username admin`.
Open http://localhost:8080. For the free local demo, include both Compose files and
follow `docs/DEMO.md`. Scan only assets you own or are explicitly authorized to test.
