# Controlled local demo

No public hosts are involved. The lab is on an internal Docker network and publishes
no service ports to the host. Nmap uses unprivileged TCP connect scanning.

## Start

```bash
python scripts/setup.py
docker compose -f docker-compose.yml -f docker-compose.demo.yml up --build -d
docker compose exec backend python -m app.cli create-user --username admin
```

Open http://localhost:8080. Add a target named **Local demo** with IP
`172.30.0.10`. Choose **Create custom profile**, name it **Demo ports**, and enter
`8000,8081,8443`. Confirm authorization; leave monitoring enabled.

The lab serves HTTP on 8000 and self-signed HTTPS on 8443. Its certificate contains
the lab IP in its SAN; certificate chain trust is not assessed.

## Baseline and equivalent observation

1. Click **Scan**. Wait for SUCCESS and INITIAL_BASELINE.
2. Inspect target details: 8000 and 8443 are visible; 8081 is closed.
3. Run another scan. Expect no service/DNS changes and the same visible services.

## Add a service

Linux/macOS:

```bash
EXTRA_SERVICE=true docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d --force-recreate lab
```

PowerShell: first set `$env:EXTRA_SERVICE='true'`, then run the same Compose command
without the `EXTRA_SERVICE=true` prefix.

Wait a few seconds, then scan again. Expect NEW_PORT for 8081. Recreating the lab
also regenerates its certificate, so TLS_RENEWED/TLS_CHANGED may appear legitimately.

## Remove a service

```bash
EXTRA_SERVICE=false docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d --force-recreate lab
```

PowerShell: set `$env:EXTRA_SERVICE='false'` before the Compose command.

Run one complete scan: the target displays **Confirming closure** and the trusted
baseline remains visible. Run a second complete scan: expect REMOVED_PORT for 8081.
Filtered/failed/partial observations do not count as confirmation.

## TLS expiry

```bash
CERT_DAYS=6 docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d --force-recreate lab
```

PowerShell: set `$env:CERT_DAYS='6'`. A scan should produce TLS_CRITICAL. Repeat with
`CERT_DAYS=20` for TLS_EXPIRING or `CERT_DAYS=0` for an expired certificate. Since
generation and scan occur at different instants, zero days is expired by scan time.
Revert to `CERT_DAYS=90` for a normal certificate.

## Safe failure demonstration

After a successful baseline, queue a scan and wait until history says RUNNING.
Immediately interrupt the worker process:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml kill -s SIGKILL worker
docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d worker
```

Expect the interrupted scan to become FAILED with SCAN_FAILED, the old trusted
baseline to remain, and no REMOVED_PORT from that failure. If the scan completed
before the kill, repeat on another RUNNING scan. `stop worker` sends SIGTERM and
allows the current scan to finish within Docker's 30-second grace period; it is
not a deterministic abrupt interruption test. Docker may kill a scan that exceeds
that grace period.
Stopping the lab may yield explicit closed ports rather
than a process failure; **do not use an ordinary closed-service observation as a
simulated scan failure**. The regression suite explicitly injects pipeline failure
and proves that it leaves the trusted baseline unchanged with no fake removals:

```bash
cd backend
python -m pytest -q tests/test_persistence.py
RUN_LIVE_LAB=1 python -m pytest -q tests/test_live_lab.py
```

These tests open local temporary ports and execute the full baseline, equivalent,
add, repeated closure and controlled failure sequence using Nmap.

## Entirely local notifications

The demo Compose override gives backend and worker identical SMTP settings, routes
worker SMTP to Mailpit without credentials, and
explicitly permits plaintext on the internal demo network. In **Notifications**,
create an SMTP rule with recipient `demo@example.test` and minimum severity LOW.
Click **Send test**. Expect SENT in history; open http://localhost:8025 to inspect
the received message. Future meaningful events will also arrive there.
SMTP should display **CONFIGURED**; Telegram/Discord remain NOT CONFIGURED unless
you deliberately supplied their settings. Only availability booleans reach the UI.

Mailpit joins both `lab` and `default` networks. The ordinary bridge enables the
published inspection port where an internal-only network did not expose it. The
web UI binds only to `127.0.0.1:8025`; SMTP 1025 is not host-published. The HTTP/TLS
lab remains solely on internal `lab`, without any host ports. Recreate old
Mailpit/API/worker containers after pulling:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d --force-recreate mailpit backend worker
docker compose -f docker-compose.yml -f docker-compose.demo.yml port mailpit 8025
```

On Windows PowerShell, open `http://localhost:8025` or run
`Invoke-WebRequest http://localhost:8025`. This addresses the reported Docker Engine
29.8.1 / Compose 5.5.1 internal-only publishing issue; CI separately checks actual
port binding, host HTTP access and receipt on its Linux Docker runner.

## Scheduled observation and cleanup

Set the target interval to five minutes and inspect its next scan time. After it is
due, verify a scan with source `scheduled` in history. Manual scans use the same
pipeline and move the next due timestamp forward.

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml down
```

This preserves the PostgreSQL volume. `down -v` deletes demo history. Unset temporary
EXTRA_SERVICE/CERT_DAYS variables when finished. If `172.30.0.0/24` conflicts with
an existing network, consistently change the subnet, lab IP, allowed CIDR and target.
