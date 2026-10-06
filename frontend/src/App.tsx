import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import {
  api,
  ApiError,
  type Certificate,
  type Dashboard,
  type Event,
  type Notification,
  type Profile,
  type Rule,
  type Scan,
  type Severity,
  type Target,
  type TargetDetail,
} from "./api";

type View =
  "Overview" | "Targets" | "Events" | "Scan history" | "Notifications";
const views: View[] = [
  "Overview",
  "Targets",
  "Events",
  "Scan history",
  "Notifications",
];
const severity: Severity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const eventTypes = [
  "INITIAL_BASELINE",
  "NEW_PORT",
  "REMOVED_PORT",
  "SERVICE_CHANGED",
  "PORT_STATE_CHANGED",
  "IP_CHANGED",
  "DNS_CHANGED",
  "TLS_RENEWED",
  "TLS_CHANGED",
  "TLS_EXPIRING",
  "TLS_CRITICAL",
  "TLS_EXPIRED",
  "TLS_HOSTNAME_MISMATCH",
  "HOST_DOWN",
  "SCAN_FAILED",
  "SCAN_PARTIAL",
];
const time = (value: string | null) =>
  value ? new Date(value).toLocaleString() : "—";
const message = (error: unknown) =>
  error instanceof Error ? error.message : "Something went wrong";
function Badge({ value }: { value: string }) {
  return (
    <span className={"badge " + value.toLowerCase().replaceAll(" ", "-")}>
      {value.replaceAll("_", " ")}
    </span>
  );
}
function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}
function Modal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", h);
    return () => document.removeEventListener("keydown", h);
  }, [onClose]);
  return (
    <div className="modal-bg" onClick={onClose}>
      <section
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="modal"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="section-heading">
          <h2>{title}</h2>
          <button onClick={onClose} aria-label="Close dialog">
            ×
          </button>
        </div>
        {children}
      </section>
    </div>
  );
}

function Login({ onLogin }: { onLogin: () => void }) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError("");
    const data = new FormData(e.currentTarget);
    try {
      await api("/auth/login", "POST", {
        username: data.get("username"),
        password: data.get("password"),
      });
      onLogin();
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="login">
      <div className="login-intro">
        <div className="logo-mark">S</div>
        <span className="eyebrow">KNOW WHEN YOUR SURFACE CHANGES</span>
        <h1>
          Visibility starts
          <br />
          with a baseline.
        </h1>
        <p>
          Track services, DNS and TLS on the assets you are authorized to
          monitor.
        </p>
        <div className="signal">
          <span />
          Local first · Your infrastructure · Your history
        </div>
      </div>
      <form className="login-form" onSubmit={submit}>
        <h2>Sign in to SurfaceWatch</h2>
        <p className="muted">Use the account created during local setup.</p>
        <label>
          Username
          <input
            name="username"
            autoComplete="username"
            required
            autoFocus
            maxLength={80}
          />
        </label>
        <label>
          Password
          <input
            name="password"
            type="password"
            autoComplete="current-password"
            required
            maxLength={256}
          />
        </label>
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        <button className="primary" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
        <p className="small muted">
          Monitor only assets you own or have explicit permission to test.
        </p>
      </form>
    </main>
  );
}

function TargetForm({
  target,
  profiles,
  onClose,
  onSave,
}: {
  target: Target | null;
  profiles: Profile[];
  onClose: () => void;
  onSave: () => void;
}) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [profile, setProfile] = useState(
    String(target?.profile_id ?? profiles[0]?.id ?? ""),
  );
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError("");
    const d = new FormData(e.currentTarget);
    try {
      let profile_id = Number(profile);
      if (profile === "custom") {
        const text = String(d.get("ports"));
        const ports: number[] = [];
        for (const item of text.split(",")) {
          const parts = item.trim().split("-");
          if (parts.length > 2 || !parts.every((p) => /^\d+$/.test(p)))
            throw new Error(
              "Use comma-separated ports or ranges, for example 22,80,8000-8003",
            );
          const start = Number(parts[0]),
            end = Number(parts[1] ?? parts[0]);
          if (start < 1 || end > 65535 || start > end || end - start > 1023)
            throw new Error("Use ports 1–65535; maximum 1024 ports");
          for (let p = start; p <= end; p++) ports.push(p);
          if (ports.length > 1024) throw new Error("Maximum 1024 ports");
        }
        const p = await api<Profile>("/profiles", "POST", {
          name: String(d.get("profile_name")),
          ports,
          description: "Custom TCP monitoring profile",
        });
        profile_id = p.id;
      }
      await api(
        target ? "/targets/" + target.id : "/targets",
        target ? "PUT" : "POST",
        {
          name: d.get("name"),
          host: d.get("host"),
          profile_id,
          interval_seconds: Number(d.get("interval")) * 60,
          enabled: d.get("enabled") === "on",
          authorized: d.get("authorized") === "on",
        },
      );
      onSave();
      onClose();
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title={target ? "Edit target" : "Add an authorized target"}
      onClose={onClose}
    >
      <form onSubmit={submit} className="form-grid">
        <label>
          Display name
          <input
            name="name"
            defaultValue={target?.name}
            required
            maxLength={120}
            placeholder="Production web server"
          />
        </label>
        <label>
          Domain or IP address
          <input
            name="host"
            defaultValue={target?.host}
            required
            maxLength={253}
            placeholder="example.com or 192.168.1.10"
          />
        </label>
        <p className="small muted">
          Use one host without a URL or subnet. Private lab addresses must be
          permitted in the server configuration.
        </p>
        <div className="two-col">
          <label>
            Scan profile
            <select
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
            >
              {profiles.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} · {p.ports.length} ports
                </option>
              ))}
              <option value="custom">Create custom profile</option>
            </select>
          </label>
          <label>
            Interval (minutes)
            <input
              name="interval"
              type="number"
              min={5}
              max={43200}
              defaultValue={(target?.interval_seconds ?? 3600) / 60}
              required
            />
          </label>
        </div>
        {profile === "custom" && (
          <>
            <label>
              Profile name
              <input
                name="profile_name"
                required
                maxLength={80}
                placeholder="Local lab"
              />
            </label>
            <label>
              TCP ports
              <input name="ports" required placeholder="22,80,443,8000-8003" />
            </label>
          </>
        )}
        <label className="checkbox">
          <input
            name="enabled"
            type="checkbox"
            defaultChecked={target?.enabled ?? true}
          />
          Enable scheduled monitoring
        </label>
        <label className="checkbox authorization">
          <input
            name="authorized"
            type="checkbox"
            required
            defaultChecked={target?.authorized ?? false}
          />
          I own this asset or have explicit permission to scan it.
        </label>
        {target && (
          <p className="small muted">
            Changing the host or profile creates a new baseline. Existing
            history stays available.
          </p>
        )}
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        <button className="primary" disabled={busy}>
          {busy ? "Saving…" : "Save target"}
        </button>
      </form>
    </Modal>
  );
}

function EventsTable({
  events,
  targets,
  onAck,
}: {
  events: Event[];
  targets: Target[];
  onAck: (id: number) => void;
}) {
  return events.length ? (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Event</th>
            <th>Target</th>
            <th>Severity</th>
            <th>Observed</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id}>
              <td>
                <strong>{e.type.replaceAll("_", " ")}</strong>
                <span className="cell-detail">{e.message}</span>
                <details>
                  <summary>Evidence</summary>
                  <pre>{JSON.stringify(e.details, null, 2)}</pre>
                </details>
              </td>
              <td>
                {targets.find((t) => t.id === e.target_id)?.name ??
                  `Target #${e.target_id}`}
              </td>
              <td>
                <Badge value={e.severity} />
              </td>
              <td className="nowrap">{time(e.created_at)}</td>
              <td>
                {e.acknowledged ? (
                  <span className="small muted">Acknowledged</span>
                ) : (
                  <button className="small" onClick={() => onAck(e.id)}>
                    Acknowledge
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <Empty>
      No changes in this view. Events appear after a scan completes.
    </Empty>
  );
}

function ScansTable({
  scans,
  onInspect,
}: {
  scans: Scan[];
  onInspect: (id: number) => void;
}) {
  return scans.length ? (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Target / scan</th>
            <th>Status</th>
            <th>Queued</th>
            <th>Duration</th>
            <th>Result</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((s) => (
            <tr key={s.id}>
              <td>
                <strong>{s.target_host}</strong>
                <span className="cell-detail">
                  #{s.id} · {s.source}
                </span>
              </td>
              <td>
                <Badge value={s.state} />
              </td>
              <td className="nowrap">{time(s.queued_at)}</td>
              <td>
                {s.duration_seconds === null
                  ? "—"
                  : `${s.duration_seconds.toFixed(1)}s`}
              </td>
              <td>
                {s.error && (
                  <span className="error cell-detail">{s.error}</span>
                )}
                <button className="small" onClick={() => onInspect(s.id)}>
                  Inspect snapshot
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <Empty>No scans yet. Add a target and run its first scan.</Empty>
  );
}

function TLSCards({ certs }: { certs: Certificate[] }) {
  return certs.length ? (
    <div className="tls-grid">
      {certs.map((c) => (
        <div className="tls-card" key={c.address + ":" + c.port}>
          <div className="section-heading">
            <strong>
              {c.address}:{c.port}
            </strong>
            <Badge value={c.status} />
          </div>
          <p>
            {c.days_remaining} days remaining · {time(c.not_after)}
          </p>
          <p className="small muted">
            {c.subject}
            <br />
            Issuer: {c.issuer}
          </p>
          {!c.hostname_matches && (
            <p className="error">Hostname mismatch: {c.hostname}</p>
          )}
          <details>
            <summary>Certificate evidence</summary>
            <p className="small">
              SAN: {c.sans.join(", ")}
              <br />
              Serial: {c.serial}
            </p>
            <code className="fingerprint">SHA256 {c.fingerprint}</code>
          </details>
        </div>
      ))}
    </div>
  ) : (
    <Empty>No direct TLS certificates collected in the trusted snapshot.</Empty>
  );
}

export default function App() {
  const [user, setUser] = useState<{ id: number; username: string } | null>(
    null,
  );
  const [checking, setChecking] = useState(true);
  const [view, setView] = useState<View>("Overview");
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [notes, setNotes] = useState<Notification[]>([]);
  const [configured, setConfigured] = useState<Record<string, boolean>>({});
  const [detailScans, setDetailScans] = useState<Scan[]>([]);
  const [detailEvents, setDetailEvents] = useState<Event[]>([]);
  const [detail, setDetail] = useState<TargetDetail | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [form, setForm] = useState<Target | null | undefined>(undefined);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [inspected, setInspected] = useState<Scan | null>(null);
  const [filters, setFilters] = useState({
    target: "",
    type: "",
    severity: "",
    since: "",
    until: "",
  });
  const [eventOffset, setEventOffset] = useState(0);
  const [scanOffset, setScanOffset] = useState(0);
  const [showArchived, setShowArchived] = useState(false);
  const refreshGeneration = useRef(0);
  const authGeneration = useRef(0);
  const activeRefresh = useRef<(() => Promise<void>) | null>(null);
  const refreshInFlight = useRef<(() => Promise<void>) | null>(null);
  const clearAccountData = useCallback(() => {
    ++refreshGeneration.current;
    activeRefresh.current = null;
    refreshInFlight.current = null;
    setDashboard(null);
    setTargets([]);
    setProfiles([]);
    setEvents([]);
    setScans([]);
    setRules([]);
    setNotes([]);
    setConfigured({});
    setDetailScans([]);
    setDetailEvents([]);
    setDetail(null);
    setSelected(null);
    setForm(undefined);
    setInspected(null);
    setFilters({ target: "", type: "", severity: "", since: "", until: "" });
    setEventOffset(0);
    setScanOffset(0);
    setShowArchived(false);
    setView("Overview");
    setError("");
    setBusy(false);
  }, []);
  const checkUser = useCallback(async () => {
    const generation = ++authGeneration.current;
    try {
      const signedIn = await api<{ id: number; username: string }>("/auth/me");
      if (generation !== authGeneration.current) return;
      // Clear before rendering authenticated content, not in a post-render effect.
      clearAccountData();
      setUser(signedIn);
    } catch (e) {
      if (generation !== authGeneration.current) return;
      clearAccountData();
      if (!(e instanceof ApiError && e.status === 401)) setError(message(e));
      setUser(null);
    } finally {
      if (generation === authGeneration.current) setChecking(false);
    }
  }, [clearAccountData]);
  useEffect(() => {
    void checkUser();
  }, [checkUser]);
  const refresh: () => Promise<void> = useCallback(async () => {
    if (
      !user ||
      activeRefresh.current !== refresh ||
      refreshInFlight.current === refresh
    )
      return;
    refreshInFlight.current = refresh;
    const generation = ++refreshGeneration.current;
    try {
      const q = new URLSearchParams({
        limit: "50",
        offset: String(eventOffset),
      });
      if (filters.target) q.set("target_id", filters.target);
      if (filters.type) q.set("event_type", filters.type);
      if (filters.severity) q.set("severity", filters.severity);
      if (filters.since) q.set("since", new Date(filters.since).toISOString());
      if (filters.until) q.set("until", new Date(filters.until).toISOString());
      const [d, t, p, e, s, r, n, c] = await Promise.all([
        api<Dashboard>("/dashboard"),
        api<Target[]>("/targets?archived=" + showArchived),
        api<Profile[]>("/profiles"),
        api<Event[]>("/events?" + q),
        api<Scan[]>("/scans?limit=50&offset=" + scanOffset),
        api<Rule[]>("/notifications/rules"),
        api<Notification[]>("/notifications"),
        api<Record<string, boolean>>("/notifications/config"),
      ]);
      if (generation !== refreshGeneration.current) return;
      setDashboard(d);
      setTargets(t);
      setProfiles(p);
      setEvents(e);
      setScans(s);
      setRules(r);
      setNotes(n);
      setConfigured(c);
      if (selected !== null) {
        const [td, ts, te] = await Promise.all([
          api<TargetDetail>("/targets/" + selected),
          api<Scan[]>("/scans?target_id=" + selected),
          api<Event[]>("/events?target_id=" + selected),
        ]);
        if (generation !== refreshGeneration.current) return;
        setDetail(td);
        setDetailScans(ts);
        setDetailEvents(te);
      }
    } catch (e) {
      if (generation !== refreshGeneration.current) return;
      if (e instanceof ApiError && e.status === 401) {
        ++authGeneration.current;
        clearAccountData();
        setUser(null);
      } else setError(message(e));
    } finally {
      if (
        refreshInFlight.current === refresh &&
        generation === refreshGeneration.current
      )
        refreshInFlight.current = null;
    }
  }, [
    user,
    filters,
    eventOffset,
    scanOffset,
    showArchived,
    selected,
    clearAccountData,
  ]);
  useEffect(() => {
    activeRefresh.current = refresh;
    void refresh();
    const timer = setInterval(() => void refresh(), 5000);
    return () => {
      clearInterval(timer);
      activeRefresh.current = null;
      refreshInFlight.current = null;
      ++refreshGeneration.current;
    };
  }, [refresh]);
  async function action(fn: () => Promise<unknown>) {
    const generation = authGeneration.current;
    setBusy(true);
    setError("");
    try {
      await fn();
      if (generation !== authGeneration.current) return;
      await refresh();
    } catch (e) {
      if (generation === authGeneration.current) setError(message(e));
    } finally {
      if (generation === authGeneration.current) setBusy(false);
    }
  }
  const scan = (id: number) =>
    action(() => api("/targets/" + id + "/scans", "POST"));
  const ack = (id: number) =>
    void action(() => api("/events/" + id + "/acknowledge", "POST"));
  const inspect = (id: number) =>
    void action(async () => {
      const generation = authGeneration.current;
      const snapshot = await api<Scan>("/scans/" + id);
      if (generation === authGeneration.current) setInspected(snapshot);
    });
  function nav(v: View) {
    setView(v);
    setSelected(null);
    setDetail(null);
  }
  async function ruleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const d = new FormData(e.currentTarget);
    const formElement = e.currentTarget;
    await action(async () => {
      await api("/notifications/rules", "POST", {
        channel: d.get("channel"),
        destination: d.get("destination"),
        min_severity: d.get("severity"),
        enabled: true,
      });
      formElement.reset();
    });
  }
  if (checking)
    return <div className="loading">Connecting to SurfaceWatch…</div>;
  if (!user)
    return (
      <>
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        <Login onLogin={() => void checkUser()} />
      </>
    );
  const activeTarget = selected === null ? null : detail;
  return (
    <div className="shell">
      <aside className="sidebar">
        <a className="brand" href="#" onClick={() => nav("Overview")}>
          <span className="logo-mark">S</span>
          <span>
            SurfaceWatch<small>SERVICE CHANGE MONITOR</small>
          </span>
        </a>
        <span className="nav-label">WORKSPACE</span>
        <nav>
          {views.map((v, i) => (
            <button
              className={view === v ? "active" : ""}
              key={v}
              onClick={() => nav(v)}
            >
              <span className="nav-icon">{["◈", "◎", "↗", "◷", "◇"][i]}</span>
              {v}
              {v === "Events" && dashboard && (
                <span className="nav-count">
                  {dashboard.recent_events.length}
                </span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="signal">
            <span />
            Local monitoring
          </div>
          <p>
            Changes are evidence.
            <br />
            Failed scans are uncertainty.
          </p>
          <a href="/api/docs" target="_blank" rel="noreferrer">
            API documentation ↗
          </a>
          <div className="user">
            <span className="avatar">{user.username[0].toUpperCase()}</span>
            <span>{user.username}</span>
            <button
              onClick={() =>
                void action(async () => {
                  const generation = authGeneration.current;
                  await api("/auth/logout", "POST");
                  if (generation !== authGeneration.current) return;
                  ++authGeneration.current;
                  clearAccountData();
                  setUser(null);
                })
              }
            >
              Sign out
            </button>
          </div>
        </div>
      </aside>
      <main className="content">
        <header className="topbar">
          <span className="eyebrow">
            SURFACEWATCH / {activeTarget ? "TARGET DETAIL" : view.toUpperCase()}
          </span>
          <span className="small muted">Refreshes every 5 seconds</span>
        </header>
        {error && (
          <div className="error-banner" role="alert">
            {error}
            <button onClick={() => setError("")} aria-label="Dismiss error">
              ×
            </button>
          </div>
        )}
        <div className="page-heading">
          <div>
            <h1>
              {activeTarget
                ? activeTarget.name
                : view === "Overview"
                  ? "Your surface, in focus."
                  : view}
            </h1>
            <p className="muted">
              {activeTarget
                ? activeTarget.host
                : view === "Overview"
                  ? "A clear record of what changed, and what needs attention."
                  : view === "Scan history"
                    ? "Every observation is retained, including uncertainty."
                    : view === "Targets"
                      ? "Monitor only assets you own or are authorized to scan."
                      : view === "Events"
                        ? "Meaningful changes against a trusted baseline."
                        : "Free delivery channels with a persistent notification history."}
            </p>
          </div>
          {!activeTarget && (
            <button className="primary" onClick={() => setForm(null)}>
              ＋ Add target
            </button>
          )}
          {activeTarget && (
            <div className="actions">
              <button
                onClick={() => {
                  setSelected(null);
                  setDetail(null);
                }}
              >
                ← Targets
              </button>
              {!activeTarget.archived && (
                <>
                  <button onClick={() => setForm(activeTarget)}>Edit</button>
                  <button
                    className="primary"
                    disabled={
                      busy ||
                      ["PENDING", "RUNNING"].includes(
                        activeTarget.latest_scan_state ?? "",
                      )
                    }
                    onClick={() => void scan(activeTarget.id)}
                  >
                    Run scan
                  </button>
                </>
              )}
            </div>
          )}
        </div>
        {activeTarget ? (
          <>
            <section className="panel target-summary">
              <div>
                <span className="eyebrow">MONITORING STATUS</span>
                <p>
                  <Badge value={activeTarget.status} />
                </p>
              </div>
              <div>
                <span className="eyebrow">TRUSTED BASELINE</span>
                <p>
                  {activeTarget.baseline_scan_id
                    ? "Scan #" + activeTarget.baseline_scan_id
                    : "Not established"}
                </p>
              </div>
              <div>
                <span className="eyebrow">RESOLVED ADDRESSES</span>
                <p>
                  {activeTarget.addresses.join(", ") || "No trusted result"}
                </p>
              </div>
              <div>
                <span className="eyebrow">NEXT SCHEDULED SCAN</span>
                <p>{time(activeTarget.next_scan_at)}</p>
              </div>
            </section>
            {activeTarget.pending_changes.length > 0 && (
              <div className="notice">
                Closure awaiting confirmation. The trusted baseline stays
                visible until a second complete observation.
              </div>
            )}
            {["FAILED", "PARTIAL"].includes(
              activeTarget.latest_scan_state ?? "",
            ) && (
              <div className="notice">
                The latest scan is uncertain. Services below come from the last
                trusted baseline; they do not imply a successful current
                observation.
              </div>
            )}
            <section className="panel">
              <div className="section-heading">
                <h2>Visible TCP services</h2>
                <span className="small muted">
                  Trusted observation ·{" "}
                  {time(activeTarget.trusted_snapshot?.observed_at ?? null)}
                </span>
              </div>
              {activeTarget.services.length ? (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Endpoint</th>
                        <th>Service</th>
                        <th>Product / version</th>
                        <th>Transport</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeTarget.services.map((s) => (
                        <tr key={s.address + ":" + s.port}>
                          <td>
                            <strong>
                              {s.address}:{s.port}
                            </strong>
                          </td>
                          <td>{s.name || "Unknown"}</td>
                          <td>
                            {[s.product, s.version].filter(Boolean).join(" ") ||
                              "Not reliably detected"}
                          </td>
                          <td>{s.tunnel === "ssl" ? "TLS / TCP" : "TCP"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Empty>
                  No accessible TCP services in the trusted snapshot.
                </Empty>
              )}
            </section>
            <section className="panel">
              <h2>TLS certificates</h2>
              <TLSCards certs={activeTarget.certificates} />
            </section>
            <section className="panel">
              <h2>DNS records</h2>
              {Object.keys(activeTarget.dns).length ? (
                Object.entries(activeTarget.dns).map(([k, v]) => (
                  <p key={k}>
                    <strong>{k}</strong>{" "}
                    <span className="muted">
                      {v.join(", ") || "No records"}
                    </span>
                  </p>
                ))
              ) : (
                <Empty>IP targets do not have DNS records.</Empty>
              )}
            </section>
            <section className="panel">
              <h2>Recent scans</h2>
              <ScansTable scans={detailScans} onInspect={inspect} />
            </section>
            <section className="panel">
              <h2>Change history</h2>
              <EventsTable
                events={detailEvents}
                targets={targets}
                onAck={ack}
              />
            </section>
          </>
        ) : view === "Overview" ? (
          <>
            <div className="metrics">
              {[
                [
                  dashboard?.monitored_targets ?? 0,
                  "Monitored targets",
                  "Configured for scheduled scans",
                ],
                [
                  dashboard?.healthy_targets ?? 0,
                  "Healthy targets",
                  "Complete trusted observations",
                ],
                [
                  dashboard?.attention_targets ?? 0,
                  "Needs attention",
                  "Changes, TLS or uncertainty",
                ],
                [
                  dashboard?.tls_warnings.length ?? 0,
                  "TLS warnings",
                  "Review certificate evidence",
                ],
              ].map(([n, label, sub], i) => (
                <div className={"metric metric-" + i} key={String(label)}>
                  <span>{label}</span>
                  <strong>{n}</strong>
                  <small>{sub}</small>
                </div>
              ))}
            </div>
            <div className="overview-grid">
              <section className="panel">
                <div className="section-heading">
                  <h2>Recent changes</h2>
                  <button className="text" onClick={() => nav("Events")}>
                    View all ↗
                  </button>
                </div>
                <EventsTable
                  events={dashboard?.recent_events ?? []}
                  targets={targets}
                  onAck={ack}
                />
              </section>
              <section className="panel">
                <div className="section-heading">
                  <h2>Monitoring pulse</h2>
                  <span className="live-dot" />
                </div>
                {dashboard?.targets.length ? (
                  dashboard.targets.map((t) => (
                    <button
                      className="pulse-row"
                      key={t.id}
                      onClick={() => {
                        setView("Targets");
                        setSelected(t.id);
                      }}
                    >
                      <div>
                        <strong>{t.name}</strong>
                        <small>{t.host}</small>
                      </div>
                      <Badge value={t.status} />
                    </button>
                  ))
                ) : (
                  <Empty>Add your first target to establish a baseline.</Empty>
                )}
                <div className="tip">
                  <strong>Trust the evidence</strong>
                  <p>
                    A timeout keeps the baseline intact. A closed port needs
                    repeated observation before a removal alert.
                  </p>
                </div>
              </section>
            </div>
            <section className="panel">
              <div className="section-heading">
                <h2>Latest scan activity</h2>
                <button className="text" onClick={() => nav("Scan history")}>
                  Scan history ↗
                </button>
              </div>
              <ScansTable scans={scans.slice(0, 5)} onInspect={inspect} />
            </section>
          </>
        ) : view === "Targets" ? (
          <section className="panel">
            <div className="section-heading">
              <h2>{showArchived ? "Archived targets" : "Your targets"}</h2>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={showArchived}
                  onChange={(e) => setShowArchived(e.target.checked)}
                />
                Show archived
              </label>
            </div>
            {targets.length ? (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Target</th>
                      <th>Status</th>
                      <th>Last scan</th>
                      <th>Next scan</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {targets.map((t) => (
                      <tr key={t.id}>
                        <td>
                          <button
                            className="target-link"
                            onClick={() => setSelected(t.id)}
                          >
                            {t.name}
                          </button>
                          <span className="cell-detail">{t.host}</span>
                          {t.latest_event && (
                            <span className="cell-detail small">
                              {t.latest_event.type.replaceAll("_", " ")}
                            </span>
                          )}
                        </td>
                        <td>
                          <Badge value={t.status} />
                        </td>
                        <td>{time(t.last_scan_at)}</td>
                        <td>{time(t.next_scan_at)}</td>
                        <td>
                          <div className="actions">
                            {!t.archived && (
                              <>
                                <button
                                  disabled={
                                    busy ||
                                    ["PENDING", "RUNNING"].includes(
                                      t.latest_scan_state ?? "",
                                    )
                                  }
                                  onClick={() => void scan(t.id)}
                                >
                                  {["PENDING", "RUNNING"].includes(
                                    t.latest_scan_state ?? "",
                                  )
                                    ? "Scanning…"
                                    : "Scan"}
                                </button>
                                <button onClick={() => setForm(t)}>Edit</button>
                                <button
                                  className="danger"
                                  onClick={() => {
                                    if (
                                      confirm(
                                        "Archive " +
                                          t.name +
                                          "? All scan and event history will be preserved.",
                                      )
                                    )
                                      void action(() =>
                                        api("/targets/" + t.id, "DELETE"),
                                      );
                                  }}
                                >
                                  Archive
                                </button>
                              </>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Empty>
                {showArchived
                  ? "No archived targets."
                  : "Your monitoring workspace is empty. Add an authorized target to begin."}
              </Empty>
            )}
          </section>
        ) : view === "Events" ? (
          <section className="panel">
            <div className="filters">
              <label>
                Target
                <select
                  value={filters.target}
                  onChange={(e) => {
                    setFilters({ ...filters, target: e.target.value });
                    setEventOffset(0);
                  }}
                >
                  <option value="">All targets</option>
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Event type
                <select
                  value={filters.type}
                  onChange={(e) => {
                    setFilters({ ...filters, type: e.target.value });
                    setEventOffset(0);
                  }}
                >
                  <option value="">All types</option>
                  {eventTypes.map((t) => (
                    <option key={t}>{t}</option>
                  ))}
                </select>
              </label>
              <label>
                Severity
                <select
                  value={filters.severity}
                  onChange={(e) => {
                    setFilters({ ...filters, severity: e.target.value });
                    setEventOffset(0);
                  }}
                >
                  <option value="">All severities</option>
                  {severity.map((s) => (
                    <option key={s}>{s}</option>
                  ))}
                </select>
              </label>
              <label>
                From
                <input
                  type="datetime-local"
                  value={filters.since}
                  onChange={(e) => {
                    setFilters({ ...filters, since: e.target.value });
                    setEventOffset(0);
                  }}
                />
              </label>
              <label>
                Until
                <input
                  type="datetime-local"
                  value={filters.until}
                  onChange={(e) => {
                    setFilters({ ...filters, until: e.target.value });
                    setEventOffset(0);
                  }}
                />
              </label>
            </div>
            <EventsTable events={events} targets={targets} onAck={ack} />
            <div className="pagination">
              <button
                disabled={!eventOffset}
                onClick={() => setEventOffset(Math.max(0, eventOffset - 50))}
              >
                Previous
              </button>
              <span>Page {eventOffset / 50 + 1}</span>
              <button
                disabled={events.length < 50}
                onClick={() => setEventOffset(eventOffset + 50)}
              >
                Next
              </button>
            </div>
          </section>
        ) : view === "Scan history" ? (
          <section className="panel">
            <div className="notice subtle">
              SUCCESS = complete observation · PARTIAL = uncertain data · FAILED
              = no trusted update. Failed scans never mean removed ports.
            </div>
            <ScansTable scans={scans} onInspect={inspect} />
            <div className="pagination">
              <button
                disabled={!scanOffset}
                onClick={() => setScanOffset(Math.max(0, scanOffset - 50))}
              >
                Previous
              </button>
              <span>Page {scanOffset / 50 + 1}</span>
              <button
                disabled={scans.length < 50}
                onClick={() => setScanOffset(scanOffset + 50)}
              >
                Next
              </button>
            </div>
          </section>
        ) : (
          <>
            <section className="panel">
              <h2>Delivery rules</h2>
              <p className="muted small">
                Credentials are configured on the server. One message groups
                meaningful events from a scan; repeated unchanged warnings are
                suppressed.
              </p>
              <div className="channel-status">
                {["smtp", "telegram", "discord"].map((c) => (
                  <span key={c}>
                    {c.toUpperCase()}{" "}
                    <Badge
                      value={configured[c] ? "CONFIGURED" : "NOT CONFIGURED"}
                    />
                  </span>
                ))}
              </div>
              {rules.map((r) => (
                <div className="rule-row" key={r.id}>
                  <div>
                    <strong>{r.channel.toUpperCase()}</strong>
                    <span className="cell-detail">
                      {r.destination || "Server-configured destination"} ·{" "}
                      {r.min_severity} and above
                    </span>
                  </div>
                  <div className="actions">
                    <button
                      onClick={() =>
                        void action(() =>
                          api("/notifications/rules/" + r.id, "PUT", {
                            channel: r.channel,
                            destination: r.destination,
                            min_severity: r.min_severity,
                            enabled: !r.enabled,
                          }),
                        )
                      }
                    >
                      {r.enabled ? "Disable" : "Enable"}
                    </button>
                    <button
                      disabled={busy || !r.enabled}
                      onClick={() =>
                        void action(() =>
                          api("/notifications/rules/" + r.id + "/test", "POST"),
                        )
                      }
                    >
                      Send test
                    </button>
                  </div>
                </div>
              ))}
              <form onSubmit={ruleSubmit} className="rule-form">
                <label>
                  Channel
                  <select name="channel">
                    <option value="smtp">SMTP email</option>
                    <option value="telegram">Telegram Bot</option>
                    <option value="discord">Discord webhook</option>
                  </select>
                </label>
                <label>
                  Email recipient (SMTP only)
                  <input
                    name="destination"
                    placeholder="you@example.com"
                    maxLength={254}
                  />
                </label>
                <label>
                  Minimum severity
                  <select name="severity" defaultValue="MEDIUM">
                    {severity.map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                </label>
                <button className="primary" disabled={busy}>
                  Add rule
                </button>
              </form>
            </section>
            <section className="panel">
              <h2>Notification history</h2>
              {notes.length ? (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Message</th>
                        <th>State</th>
                        <th>Attempts</th>
                        <th>Created</th>
                      </tr>
                    </thead>
                    <tbody>
                      {notes.map((n) => (
                        <tr key={n.id}>
                          <td>
                            <span className="notification-text">
                              {n.payload}
                            </span>
                            {n.error && (
                              <span className="error cell-detail">
                                {n.error}
                              </span>
                            )}
                          </td>
                          <td>
                            <Badge value={n.state} />
                          </td>
                          <td>{n.attempts}</td>
                          <td>{time(n.created_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Empty>
                  No notifications yet. Create a rule and send a test.
                </Empty>
              )}
            </section>
          </>
        )}
        <footer>
          SurfaceWatch · Detect changes. Preserve evidence. Monitor with
          permission.
        </footer>
      </main>
      {form !== undefined && (
        <TargetForm
          target={form}
          profiles={profiles}
          onClose={() => setForm(undefined)}
          onSave={() => void refresh()}
        />
      )}{" "}
      {inspected && (
        <Modal
          title={"Scan #" + inspected.id + " · " + inspected.state}
          onClose={() => setInspected(null)}
        >
          <p>
            {inspected.target_host} · {time(inspected.finished_at)}
          </p>
          {inspected.error && <p className="error">{inspected.error}</p>}
          <p className="small muted">
            Immutable observation. Only complete trusted results can update the
            baseline.
          </p>
          <pre className="snapshot-json">
            {JSON.stringify(
              inspected.snapshot ?? { state: inspected.state },
              null,
              2,
            )}
          </pre>
        </Modal>
      )}
    </div>
  );
}
