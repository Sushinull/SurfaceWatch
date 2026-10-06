SurfaceWatch V1 is frozen for authorized local portfolio and small-lab monitoring.

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
