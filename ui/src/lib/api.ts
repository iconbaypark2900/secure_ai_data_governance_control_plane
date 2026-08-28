/**
 * The API client.
 *
 * The admin key is held in memory and mirrored to sessionStorage rather than
 * localStorage: it survives a page reload, and it does not survive the tab
 * closing. An admin credential that outlives the session it was typed into is
 * a credential nobody remembers granting.
 */

const KEY_STORAGE = "cp.adminKey";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }

  get isAuthError(): boolean {
    return this.status === 401 || this.status === 403;
  }
}

let apiKey: string = sessionStorage.getItem(KEY_STORAGE) ?? "";

export function setApiKey(key: string): void {
  apiKey = key.trim();
  if (apiKey) sessionStorage.setItem(KEY_STORAGE, apiKey);
  else sessionStorage.removeItem(KEY_STORAGE);
}

export function getApiKey(): string {
  return apiKey;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  if (apiKey) headers.set("X-API-Key", apiKey);

  const response = await fetch(`/v1${path}`, { ...init, headers });

  if (response.status === 204) return undefined as T;
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;

  if (!response.ok) {
    const detail =
      typeof body?.detail === "string"
        ? body.detail
        : JSON.stringify(body?.detail ?? body ?? response.statusText);
    throw new ApiError(response.status, detail);
  }
  return body as T;
}

export const api = {
  health: () => request<Health>("/health"),
  ready: () => request<Ready>("/ready"),

  policies: () => request<Policy[]>("/policies"),
  policySchema: () => request<PolicySchema>("/policies/schema"),
  policyVersions: (key: string) => request<PolicyVersion[]>(`/policies/${key}/versions`),
  setPolicyEnabled: (key: string, enabled: boolean) =>
    request<Policy>(`/policies/${key}/enabled?enabled=${enabled}`, { method: "POST" }),

  assets: (params: Record<string, string> = {}) =>
    request<Asset[]>(`/assets?${new URLSearchParams(params)}`),
  resolveAsset: (urn: string) =>
    request<ResolvedAsset>(`/assets/resolve?urn=${encodeURIComponent(urn)}`),
  principals: () => request<Principal[]>("/principals"),

  decisions: (params: Record<string, string> = {}) =>
    request<Page<DecisionSummary>>(`/decisions?${new URLSearchParams(params)}`),
  decision: (id: string) => request<DecisionDetail>(`/decisions/${id}`),
  decisionStats: () => request<DecisionStats>("/decisions/stats"),

  decide: (body: unknown) => request<DecideResponse>("/decide", {
    method: "POST",
    body: JSON.stringify(body),
  }),
  simulate: (body: unknown) => request<SimulateResponse>("/simulate", {
    method: "POST",
    body: JSON.stringify(body),
  }),
  classify: (payload: unknown) =>
    request<ClassifyResponse>("/classify", {
      method: "POST",
      body: JSON.stringify({ payload }),
    }),

  audit: (params: Record<string, string> = {}) =>
    request<Page<AuditRecord>>(`/audit?${new URLSearchParams(params)}`),
  verifyAudit: () => request<ChainVerification>("/audit/verify"),

  approvals: () => request<Approval[]>("/approvals"),
  resolveApproval: (id: string, grant: boolean, note: string) =>
    request<Approval>(`/approvals/${id}/decide?grant=${grant}`, {
      method: "POST",
      body: JSON.stringify({ note }),
    }),

  taxonomy: () => request<Taxonomy>("/meta/taxonomy"),
};

// --- types ------------------------------------------------------------------

export type Effect = "allow" | "deny" | "require_approval";

export interface Health { status: string; service: string; environment: string }
export interface Ready {
  status: string; database: string; default_effect: string; fail_closed: boolean;
}

export interface Policy {
  key: string; name: string; description: string; effect: Effect;
  priority: number; enabled: boolean; version: number; tags: string[];
  document: Record<string, unknown>;
  created_by: string; updated_by: string;
  created_at: string | null; updated_at: string | null;
}

export interface PolicyVersion {
  policy_key: string; version: number; document: Record<string, unknown>;
  change_note: string; changed_by: string; created_at: string | null;
}

export interface PolicySchema {
  selectors: string[]; operators: string[]; effects: string[];
  combinators: string[]; obligation_types: string[]; redaction_strategies: string[];
  labels: LabelInfo[];
}

export interface LabelInfo {
  key: string; name: string; category: string; severity: string;
  description: string; regulations: string[];
  detectors?: string[]; automatically_detected?: boolean;
}

export interface Classification {
  label: string; source: string; confidence: number;
  asserted_by: string; evidence: Record<string, unknown>;
}

export interface Asset {
  urn: string; name: string; kind: string; owner: string; description: string;
  attributes: Record<string, unknown>;
  classifications: Classification[]; labels: string[]; regulations: string[];
  last_scanned_at: string | null; created_at: string | null;
}

export interface ResolvedAsset {
  urn: string; registered: boolean; kind: string;
  classifications: string[]; confidence: Record<string, number>;
  matched_patterns: string[]; attributes: Record<string, unknown>;
  regulations: string[];
}

export interface Principal {
  external_id: string; type: string; display_name: string; description: string;
  attributes: Record<string, unknown>; enabled: boolean;
}

export interface Page<T> { total: number; limit: number; offset: number; items: T[] }

export interface DecisionSummary {
  id: string; created_at: string | null;
  principal_id: string; principal_type: string; action: string; resource_urn: string;
  effect: Effect; reason: string;
  determining_policy: string | null; matched_policies: string[];
  obligations: Record<string, unknown>[]; classifications: string[];
  finding_count: number; redaction_count: number; latency_ms: number;
  correlation_id: string | null;
}

export interface DecisionDetail extends DecisionSummary {
  trace: { trace?: TraceEntry[]; reason?: string } | null;
  context: Record<string, unknown>;
}

export interface TraceEntry {
  key: string; name: string; effect: Effect; priority: number;
  matched: boolean; reason: string;
  conditions: { selector: string; operator: string; passed: boolean; description: string }[];
}

export interface DecisionStats {
  total: number; avg_latency_ms: number; total_redactions: number;
  by_effect: Record<string, number>;
  by_policy: { policy: string; count: number }[];
}

export interface Finding {
  label: string; detector: string; start: number; end: number;
  confidence: number; path: string; preview: string; severity: string;
}

export interface DecideResponse {
  decision_id: string | null; effect: Effect; reason: string;
  determining_policy: string | null; matched_policies: string[];
  obligations: Record<string, unknown>[];
  classifications: string[]; findings: Finding[]; regulations: string[];
  payload: unknown; redactions: Record<string, unknown>[];
  unsupported_obligations: string[];
  explain: { trace?: TraceEntry[] } | null;
  latency_ms: number; policy_errors: string[];
}

export interface SimulateResponse {
  decision: DecideResponse; baseline: DecideResponse | null;
  changed: boolean; policies_evaluated: number;
}

export interface ClassifyResponse {
  findings: Finding[]; labels: string[]; label_counts: Record<string, number>;
  max_severity: string | null; regulations: string[];
  scanned_chars: number; truncated: boolean;
}

export interface AuditRecord {
  seq: number; timestamp: string; event: string; actor: string; subject: string;
  payload: Record<string, unknown>; prev_hash: string; record_hash: string;
}

export interface ChainVerification {
  valid: boolean; checked: number; corrupted: number[];
  broken_links: number[]; sequence_errors: number[]; message: string;
}

export interface Approval {
  id: string; decision_id: string; status: string; requested_by: string;
  justification: string; decided_by: string | null; decision_note: string;
  created_at: string | null; resolved_at: string | null; expires_at: string | null;
  decision?: {
    action: string; resource_urn: string; principal_id: string;
    classifications: string[]; reason: string; determining_policy: string | null;
  };
}

export interface Taxonomy { categories: string[]; severities: string[]; labels: LabelInfo[] }
