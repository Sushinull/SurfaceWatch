# Troubleshooting

| Symptom | Check / action |
|---|---|
| Compose requests a password variable | Run `python scripts/setup.py` in the repository root. Existing `.env` is preserved. |
| Login unavailable | Create a user with `docker compose exec backend python -m app.cli create-user --username admin`. No seeded default password exists. |
| Invalid origin / missing X-SurfaceWatch | Use the configured APP_ORIGIN exactly. Browser code adds the header; CLI writes must add `-H 'X-SurfaceWatch: 1'`. Native Vite needs APP_ORIGIN `http://localhost:5173`. |
| Too many login attempts | Wait one minute; the local process allows five per IP and 30 globally per minute. |
| Target outside permitted ranges | Add the authorized narrow CIDR to ALLOWED_TARGET_CIDRS, recreate backend/worker, scan again. A domain's every resolved address must be allowed. |
| DNS failure / too many addresses | Check resolver connectivity and address count. Use explicit authorized IP targets for a large CDN; no partial address-set scanning is silently accepted. |
| Nmap missing | Use the backend Docker image, or install Nmap and ensure it is on the native worker PATH. |
| Repeated PARTIAL | Inspect scan errors. TLS failures, filtered states, missing XML coverage or one failed address retain the old baseline. Verify the lab/target and profile. |
| Target shows Confirming closure | Run a second complete scan. PARTIAL/FAILED resets candidate observations. Review current evidence before assuming removal. |
| Scan stays PENDING | Check `docker compose logs worker`; ensure one worker is running and migrations completed. |
| Second worker exits | Expected: one V1 worker owns an advisory lock. Use the existing worker instead of scaling replicas. |
| Slow scans | Timeout is per IP; maximum eight IPs by default. Use narrower profiles, explicit IPs or fewer targets. Service detection may need time even on local ports. |
| SCAN_FAILED after restart | Interrupted RUNNING jobs are recorded as failed. The prior baseline remains. Queue a new scan. |
| RUNNING after a transient completion DB error | v1.0.1 recovers the orphaned job at the next worker tick. Losing the advisory-lock connection exits the worker; Docker restarts it. Restore DB connectivity and inspect logs; do not reset volumes. |
| TLS card disagrees with custom thresholds | Rebuild both backend/frontend at v1.0.1; certificate bands now use the server's thresholds. |
| Notification stays PENDING / FAILED | Inspect attempts and logs; configure SMTP credentials/STARTTLS or Telegram/Discord settings, recreate backend and worker, use Send test. CONFIGURED means settings are present, not verified connectivity. |
| Mailpit 8025 configured but unreachable / `docker port` empty | Pull the V1 fix and recreate Mailpit with both Compose files. It must join `lab` and `default`; internal-only attachment reproduced this symptom on the reported Engine 29.8.1 / Compose 5.5.1 setup. Verify `port mailpit 8025` and host HTTP access. Do not publish SMTP or lab ports. |
| SMTP delivered but badge says NOT CONFIGURED | Backend and worker must load the same channel settings. The demo now shares one SMTP anchor. Recreate both with both Compose files; do not edit UI state or expose credentials. |
| Stop/restart did not create SCAN_FAILED | SIGTERM may finish the current scan within Docker's 30-second grace period. For deterministic abrupt recovery, wait for RUNNING, use `kill -s SIGKILL worker`, then start worker. A queued PENDING job was not interrupted. |
| SMTP needs plaintext | Keep production STARTTLS enabled. Only an explicitly trusted local SMTP lab should use SMTP_ALLOW_PLAINTEXT=true and SMTP_STARTTLS=false. |
| Docker lab subnet conflict | Change Compose subnet, lab address, ALLOWED_TARGET_CIDRS and target together. |
| Docker permission/network issue | Use TCP connect scanning. No raw-socket privileges are needed. Container IPv6 needs a reachable IPv6 network; native scanning may be easier. |
| PostgreSQL authentication changed | Existing volumes retain the original database password. Restore the correct `.env` or change the DB role password; editing POSTGRES_PASSWORD does not change an initialized volume. |
| Data disappeared after reset | `docker compose down -v` deletes the database volume. Restore your private pg_dump backup. |

Useful commands:

```bash
docker compose ps
docker compose logs --tail=100 backend worker migrate
docker compose exec backend python -m alembic current
docker compose run --rm migrate
docker compose exec backend python -m app.cli reset-password --username admin
```

For the demo, include `-f docker-compose.yml -f docker-compose.demo.yml` consistently
when starting/recreating the full stack. Do not paste `.env`, passwords, Telegram
tokens or Discord webhook URLs into bug reports.

PowerShell environment syntax is `$env:EXTRA_SERVICE='true'` or `$env:CERT_DAYS='6'`
before Compose; use `Remove-Item Env:EXTRA_SERVICE` / `Remove-Item Env:CERT_DAYS`
afterward. `down` preserves history, while `down -v` deletes it. Changing
POSTGRES_PASSWORD in `.env` does not update an existing database role.
