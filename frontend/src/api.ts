export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export interface Event {
  id: number;
  target_id: number;
  scan_id: number;
  type: string;
  severity: Severity;
  message: string;
  details: Record<string, unknown>;
  acknowledged: boolean;
  created_at: string;
}
export interface Target {
  id: number;
  name: string;
  host: string;
  profile_id: number;
  enabled: boolean;
  authorized: true;
  archived: boolean;
  interval_seconds: number;
  status: string;
  latest_scan_state: string | null;
  last_scan_at: string | null;
  next_scan_at: string | null;
  baseline_scan_id: number | null;
  latest_event: Event | null;
  pending_changes: { observations: number; details: Record<string, unknown> }[];
}
export interface Service {
  address: string;
  port: number;
  protocol: string;
  state: string;
  name: string;
  product: string;
  version: string;
  tunnel: string;
  confidence: number;
}
export interface Certificate {
  address: string;
  port: number;
  hostname: string;
  subject: string;
  issuer: string;
  serial: string;
  fingerprint: string;
  not_before: string;
  not_after: string;
  sans: string[];
  hostname_matches: boolean;
  days_remaining: number;
  status: "EXPIRED" | "CRITICAL" | "WARNING" | "VALID";
}
export interface Snapshot {
  state: string;
  observed_at: string;
  addresses: string[];
  dns: Record<string, string[]>;
  ports: number[];
  services: Service[];
  certificates: Certificate[];
  errors: string[];
}
export interface TargetDetail extends Target {
  services: Service[];
  certificates: Certificate[];
  addresses: string[];
  dns: Record<string, string[]>;
  trusted_snapshot: Snapshot | null;
}
export interface Scan {
  id: number;
  target_id: number;
  target_host: string;
  state: string;
  source: string;
  queued_at: string;
  finished_at: string | null;
  duration_seconds: number | null;
  error: string | null;
  ports: number[];
  snapshot?: Snapshot | null;
}
export interface Profile {
  id: number;
  name: string;
  ports: number[];
  description: string;
}
export interface Rule {
  id: number;
  channel: "smtp" | "telegram" | "discord";
  destination: string;
  min_severity: Severity;
  enabled: boolean;
}
export interface Notification {
  id: number;
  rule_id: number;
  state: string;
  attempts: number;
  error: string | null;
  created_at: string;
  sent_at: string | null;
  payload: string;
}
export interface Dashboard {
  total_targets: number;
  monitored_targets: number;
  healthy_targets: number;
  attention_targets: number;
  recent_events: Event[];
  targets: Target[];
  tls_warnings: Event[];
}
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
export async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const response = await fetch("/api" + path, {
    method,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-SurfaceWatch": "1" },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  if (!response.ok) {
    const data = await response
      .json()
      .catch(() => ({ detail: "Request failed" }));
    throw new ApiError(
      response.status,
      typeof data.detail === "string"
        ? data.detail
        : "Check the form fields and try again",
    );
  }
  return response.status === 204 ? (undefined as T) : response.json();
}
