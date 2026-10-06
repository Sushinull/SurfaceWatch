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
| Notification stays PENDING / FAILED | Inspect attempts and logs; configure SMTP credentials/STARTTLS or Telegram/Discord settings, recreate worker, use Send test. |
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
