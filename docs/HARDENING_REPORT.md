# SurfaceWatch V1 hardening / v1.0.1

Date: 2026-10-06. Scope: backward-compatible correctness, security, reliability,
portability and test coverage for trusted local operators. No V2 features, schema
change or UI redesign.

## Base and provenance

Actual GitHub main at audit start and dereferenced annotated `v1.0.0` both pointed
to `4577703c25e73b17c14a201d71dd99f335f337d3`, tree
`9d5e3468a01e2cdcdbdc5beeac39c7af442baf65`. There were no later main commits.
The clean local checkout had the identical source tree. Old annotated tag object:
`94f5d697ea379d83644b10350bd423d064835e4d`; it must remain unchanged.

The original dependencies/tests were reinstalled and rerun before patching:
**78 backend tests passed**, including real Nmap/TLS/SMTP, in 36.37 seconds.
Frontend npm ci, TypeScript/Vite, Prettier and npm audit also passed. Existing CI
was inspected but is not substituted for this patch's fresh exact-SHA verification.

## Confirmed bugs

Severity reflects the local deployment boundary. No critical/high exploitable
finding was confirmed. Each fix has focused regression coverage.

| ID / severity | Reproduction / impact | Root cause / fix | Regression |
|---|---|---|---|
| H01 MEDIUM | Session A caches RUNNING, B finishes FAILED, A overwrites it with SUCCESS and promotes baseline. | Stale `db.get` identity. Lock target then scan, refresh persisted identities, reject completed jobs. | Stale-session regression and real PG concurrent finish (one succeeds, one rejected). |
| H02 MEDIUM | DB completion error after RUNNING commit leaves a job stuck across later ticks. | Recovery only at startup. Recover orphaned RUNNING at each serial tick boundary; FAILED retains baseline. | Pre-completion DB failure, next-tick recovery and later successful work; post-commit error does not recover SUCCESS. |
| H03 MEDIUM | Critical cert, FAILED/PARTIAL, same cert emits duplicate TLS warning/outbox entry. | Uncertainty cleared active fingerprints. Preserve latches until complete SUCCESS proves resolution. | Both states, notification counts, later resolution/reoccurrence; Docker unchanged warning remains exactly once after interruption. |
| H04 MEDIUM | Unacknowledged HIGH followed by LOW incorrectly shows Healthy. | Only latest event checked. Query any unacknowledged MEDIUM/HIGH/CRITICAL for attention. | Status stays Changes detected until HIGH acknowledged. |
| H05 LOW | Overlong login password is echoed in 422 response. | Default validation exposes rejected input/context. Return field/type/message only. | Password sentinel absent from response. Caller-input reflection; no other-user password exposure demonstrated. |
| H06 MEDIUM | Invalid settings print rejected secrets, including model-level input mappings. | Default Pydantic error text. Enable `hide_input_in_errors`. | Invalid SECRET_KEY and model-level SMTP-password sentinel tests. |
| H07 MEDIUM | Uvicorn exception logging bypasses safe root formatter and prints credential-bearing exception text. | Own non-propagating handlers. Route error logging through safe JSON; retain disabled access logging. | Actual exception/sentinel with independent Uvicorn handler. |
| H08 LOW | Whitespace-only profile name succeeds, creating blank selector labels. | Missing name normalization. Strip/reject blank names. | POST returns 422; existing historical profiles retained. |
| H09 MEDIUM | Delayed real HIGH response overwrites newer LOW filter results. | Unprotected in-flight refresh. Guard generation/context and serialize same-context polling. | Old Chromium UI reproduced failure; patch rejects obsolete responses. Detail/error responses guarded too. |
| H10 MEDIUM | critical=14/warning=60 yields incorrect UI bands for 10/45-day certificates. | UI hardcoded 7/30. API computes configured current band; UI consumes it. | Custom-threshold API cases and browser authoritative-band fixture. |
| H11 LOW | Nine rules plus two simultaneous POSTs both return 201, creating 11 rules. | Count/insert not serialized. Lock owner through PostgreSQL count/commit. | Actual API race: 201+409, exactly 10; SQLite reproduced old race but does not implement deployment row locks. |
| H12 LOW | At 390 px the Sign out button cannot be reached. | Mobile CSS hides its entire parent. Keep account controls visible while hiding decorative sidebar content. | Real mobile Playwright logout plus revoked-cookie 401. |

Eight original backend findings produced nine failing regressions. H10 added two
failing cases, H09 failed on the old UI, H11 was reproduced using real concurrent
requests/count queries, and H12 failed as a real mobile button timeout. No mock
count or fabricated security exploit is presented as a confirmed finding.

## Non-issues / intentional V1 boundaries

- Auth/ownership covers writes, archive/scan, snapshots, events/acknowledgment,
  rules/tests and related history. Existing CSRF/origin, expiry/logout and throttle
  checks remain in place; no IDOR bypass was found.
- DNS A/AAAA/CNAME resolves once, all endpoints pass policy, Nmap/TLS use numeric
  pinned IPs with original SNI. Mixed forbidden answers, DNS errors or excess
  addresses fail before probing. Decimal/octal-like numeric hosts are rejected;
  a hex-like valid DNS label still uses DNS/policy, never libc numeric parsing.
- Broad CIDRs do not allow mapped metadata/multicast/unspecified endpoints. Explicit
  private/lab CIDRs deliberately authorize other private endpoints.
- Missing Nmap, permissions, timeout, killed/nonzero process, malformed/incomplete
  XML and TLS uncertainty never promote baseline or infer REMOVED_PORT.
- Closure counts are independent per endpoint; reopen clears candidates and
  FAILED/PARTIAL reset confirmation. Lost IP/port scope is not explicit closure.
- Seeded 100-iteration equivalence tests cover DNS order/duplicates/case, service
  whitespace, service/port/SAN order and observation time, while real changes
  still emit. TLS exact instants/timezones and configured bands are tested.
- A single advisory-locked worker is the outbox claim boundary; a real PG test
  rejects a second lock owner. Two unsupported independent dispatchers are not V1.
  Physical rule deletion with outbox references is blocked by PG foreign keys;
  there is no rule-deletion API.
- Disabled scheduling permits explicit manual scans. Archive preserves history
  and rejects new scans. Shared immutable profiles belong to trusted local users,
  not isolated tenants. Historical TLS warning count is unacknowledged events,
  not the current certificate count.

## Verification

Collection: **174 tests**, including **10 PG-only concurrency/FK/advisory-lock tests**
and **3 live integrations**. Local full suite: **164 passed, 10 skipped**. Standard
local fixture suite: 161 passed, 13 skips (PG + live). Nmap/TLS/SMTP really run in
the full suite. Counts must be confirmed again after the final change.

Ruff, TypeScript/Vite, Prettier and actionlint pass locally. pip-audit finds no
known production-requirement vulnerabilities; npm audit reports zero including
development dependencies. No major dependency upgrade was made. One Starlette/HTTPX
test-client deprecation warning remains. Audits are point-in-time, not guarantees.
Image tags/Python transitives remain mutable; no container OS vulnerability scanner
is installed here, so package audits do not certify every image layer.

The local host has no Docker daemon/native PostgreSQL server. GitHub CI runs PG17,
Alembic upgrade/check plus disposable downgrade/re-upgrade, full suite, fresh pulled
no-cache builds, base/merged Compose, clean startup, Mailpit sender/recipient/body,
scheduler and real SIGKILL. Expanded acceptance checks idle SIGTERM, durable PENDING
restart, real DB stop/start and worker completion while API is stopped. Fault
injection covers pre/post-completion commit and delivery-acceptance/rollback windows.
A real host reboot or precisely timed SIGKILL between individual commits is not
claimed. External acceptance followed by rollback really resends: at least once.

Browser checks actual API/worker/Nmap/TLS/SMTP locally and Docker/PG in CI: login,
channel badges, the newly requested SMTP notification ID (not an older SENT badge),
details/snapshot, filter race, configured TLS band, creation, policy-denied scan
error, edit/disable/archive/preserved history and mobile logout. All five views
are checked for document overflow at 390 px. Custom TLS-band UI uses an API fixture;
backend custom-band computation is independently tested.

Windows target **Engine 29.8.1 / Compose 5.5.1**: this host cannot independently
rerun Windows. Prior operator acceptance is historical evidence. Networking/bindings
remain unchanged: Mailpit `lab` + `default`, only `127.0.0.1:8025`, SMTP 1025
unpublished, lab HTTP/TLS only on internal `lab`. Linux CI records actual versions
and verifies effective config, host reachability and SMTP; it is not a Windows run.

## Verified candidate checkpoint

Candidate source `3e2d940c26ac59d6646bd7b7a6e0038ae0a0eb0d` passed all three jobs in
[fresh CI run 37496852792](https://github.com/Sushinull/SurfaceWatch/actions/runs/37496852792).
Native PostgreSQL 17: **174 passed**, no skips, 59.27 seconds. Alembic upgrade/check
and disposable downgrade/re-upgrade/check passed without schema drift. Frontend
install/build/format/audit passed. Docker no-cache build/config/startup, all original
and expanded acceptance scenarios, real Mailpit, scheduler, SIGKILL/SIGTERM/PENDING,
DB restart, API outage and browser passed. Actual Linux Engine **28.0.4**, Compose
**2.38.2**, CI Chromium **151.0.7922.34**; local Chromium **143** and Nmap **7.94SVN**.

This candidate proof is followed by a fresh run on the final release commit.
[The v1.0.1 Release](https://github.com/Sushinull/SurfaceWatch/releases/tag/v1.0.1)
records that exact final SHA and CI URL after the gate succeeds. Do not substitute
the candidate run for final-SHA verification.

## Security / hygiene

All nine remote historical commits and 95 unique blobs (94 text, one PNG) were
enumerated. Text was inspected locally or fetched for one missing historical blob.
No tracked `.env`, private keys, dumps/user data or real credential patterns were
found. Test/CI/example sentinels are not production credentials. Current tracked
source, ignore rules and generated artifacts were reviewed. Pattern/manual inspection
is not an exhaustive proof against arbitrary encoded credentials.

Safe validation/logging, boolean-only channel status, fixed provider hosts, disabled
redirect/environment proxy, SMTP TLS policy and Discord mention suppression have
coverage. No confirmed critical/high exploitable defect remains in this local scope.
Keep services local, permit narrow CIDRs, and retain ownership/authorization checks.

## Reliability and known V1 limitations

Only complete SUCCESS can advance baseline; closure holds it until confirmation.
Uncertainty clears closure candidates while retaining ongoing alert latches. Completed
scan, child evidence, events, baseline and outbox commit atomically. A prior failed
completion is recovered on the next tick; a committed SUCCESS is never overwritten.
PG tests exercise manual/manual, manual/scheduled, scheduler/scheduler, duplicate
finish, edit/archive versus queue, duplicate target create and rule-cap concurrency.

Whole-snapshot holding can delay or omit rapid overlapping reversals: A closes twice
while B begins closure, then A reopens as B confirms. The old held baseline can still
show A open, so that reopening need not emit NEW_PORT. This coverage limitation needs
endpoint-level trust in V2; it does not manufacture closure from uncertain evidence.

Other limits: one serial worker/per-address deadlines; direct TLS without STARTTLS
or chain/revocation assessment; at-least-once notification duplication after acceptance
before commit; no automatic retention or signed evidence; mutable image/transitive
resolution; trusted local/shared-profile boundary; DB admins can alter state directly.
SIGTERM requests tick completion but Docker can kill long work after its 30-second
grace period; recovery marks it FAILED and retains its baseline.

## Release gate

`v1.0.0` stays immutable. The separate v1.0.1 workflow requires the exact release
message, successful backend/frontend/docker jobs on that SHA, clean checkout and
main HEAD still equal to it. It verifies the old annotated tag object and target
before and after publishing, refuses an existing patch tag, then creates an annotated
v1.0.1 and Release. The release body appends final SHA and fresh CI URL.

Until the final exact-SHA run completes, local checks do not mean this gate passed.
The GitHub Release and associated CI runs supply the authoritative final proof.
