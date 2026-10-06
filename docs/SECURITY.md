# Authorized-use boundary and security

Use SurfaceWatch only with assets you own or have explicit authorization to scan.
The tool performs bounded TCP connection/service observation and direct TLS
handshakes. It performs no exploitation, credential attack, persistence, stealth,
vulnerability probing workflow or large-scale discovery.

## Implemented controls

- Domain/IP-only target syntax; reject URLs, CIDRs, flags, wildcards, delimiters,
  shell substitutions, path syntax and IPv6 zone identifiers.
- Fixed Nmap argument arrays with numeric validated IPs; no shell interpolation
  and no caller-supplied Nmap flags. No full-port default scan.
- Resolve once, validate every address and pin Nmap/TLS connections to it. Reject
  private targets unless explicitly permitted by operator CIDRs. Never probe
  unspecified, multicast or the common metadata endpoint.
- Reject partial DNS/address/port coverage instead of silently truncating it.
- Argon2 password hashing, CLI-only account creation/reset, rate-limited login,
  HttpOnly SameSite=Strict cookies, random session tokens stored as HMAC hashes,
  fixed expiry and session revocation on logout/password reset.
- CSRF defenses: every write requires X-SurfaceWatch, browser Origin must match
  APP_ORIGIN, and CORS is not enabled. Same-origin browser proxy.
- User ownership checks on targets, scans, events and notification rules.
- SQLAlchemy parameter binding, Pydantic input limits and output models, React
  text escaping, no raw HTML insertion, Nginx body limit and CSP.
- defusedxml parser, conservative state classification, confirmation before closure.
- Random generated secrets in an ignored environment file; SMTP/Telegram/Discord
  credentials are operator settings, never returned to the browser or stored in rules.
- Sanitized notification errors and request logs omit exception texts/credentials.
- Non-root backend/frontend/demo containers; no privileged scanning, no capabilities
  for application containers, no-new-privileges, read-only filesystem and tmpfs.
- Loopback-only published UI/database/mail inspection ports; internal demo network.
- Hard endpoint denials also inspect IPv4-mapped IPv6, preventing mapped metadata,
  multicast or unspecified IPv4 endpoints from bypassing those rules.

Mailpit joins the normal bridge for loopback publishing; lab HTTP/TLS services stay
internal and SMTP 1025 is not published. Backend/worker share demo settings with
empty SMTP credentials. Use plaintext SMTP only for this trusted local lab. Keep
the unauthenticated Mailpit UI local. Channel status returns only booleans, never
passwords, tokens or webhook URLs.

## Operator responsibilities and limitations

Private-range permission is deliberate: this is a local scanner, so operators may
need to monitor LAN/lab hosts. Grant narrow CIDRs. Allowing a range is a network
policy decision; the authorization checkbox is an acknowledgment, not proof of
ownership. Public unicast scanning is permitted to authenticated trusted operators.

V1 is for trusted local users, not a public multi-tenant service. Do not publish the
API or dashboard on the internet. HTTPS, stronger distributed rate limits, access
auditing, scan authorization workflows and a separate network-enforced allowlist
would be needed for that deployment model. Default HTTP cookies are appropriate
only for loopback development; set COOKIE_SECURE with an HTTPS deployment.

TLS inspection deliberately accepts invalid certificates solely to collect evidence.
It does not send secrets or application data. Hostname monitoring does not establish
chain trust/revocation; direct TLS only, no SMTP/IMAP STARTTLS. A certificate renewal
event does not prove that the replacement certificate is trustworthy.

The database stores domain/IPs, certificate and service evidence. Keep its volume,
backups and `.env` private. Completed snapshots are immutable through the app, but
database administrators can modify them. There is no signed evidence ledger.
Notification delivery is at least once; a crash after external acceptance but before
commit can duplicate a message. A TLS handshake failure conservatively makes the
whole scan PARTIAL, temporarily delaying service comparisons on that target.

The standard SQL fixture suite uses SQLite only for test isolation. PostgreSQL is
required in real deployments. One serial worker can be delayed by slow multi-IP
targets; scanning deadlines are per address. Monitor logs and do not oversubscribe.

## Dependency verification

Pinned direct backend requirements and a frontend lockfile improve repeatability.
Backend transitive dependencies and base-image tags are resolved at build time;
V1 freezes the source, not every future dependency/image resolution.
Dependency audits were run during development; consult the final report for results.
They are a point-in-time check, not proof of absence of vulnerabilities. Update
dependencies and base images deliberately, then rerun migrations and tests.

For a suspected issue, report it privately to the repository owner with a minimal
local reproduction. Do not include real credentials or unauthorized target results.
