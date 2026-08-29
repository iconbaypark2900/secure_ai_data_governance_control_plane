/**
 * The wire contract, as types.
 *
 * Deliberately a mirror of the Python SDK's `_build_body` rather than an
 * independent design. Two clients that disagree about the request body are two
 * clients that get different decisions from the same policy, and the one that
 * gets used less is the one that stays wrong.
 */

export type Effect = "allow" | "deny" | "require_approval";

/** What actually happened to a decision, reported back after the fact. */
export const Outcome = {
  ENFORCED: "enforced",
  REFUSED: "refused",
  PARTIAL: "partial",
} as const;
export type OutcomeValue = (typeof Outcome)[keyof typeof Outcome];

/** Approval states from which nothing further will change on its own. */
export const TERMINAL_APPROVAL_STATES: ReadonlySet<string> = new Set([
  "granted",
  "denied",
  "expired",
]);

/**
 * Obligations this client can treat as already satisfied, because the control
 * plane applied them to the payload it returned. Everything else is the
 * enforcement point's own duty and must be declared.
 */
export const SATISFIED_BY_CONTROL_PLANE: ReadonlySet<string> = new Set([
  "redact",
  "annotate",
  "log",
  "ttl",
]);

export interface Obligation {
  type?: string;
  [key: string]: unknown;
}

export interface Redaction {
  label?: string;
  count?: number;
  strategy?: string;
  [key: string]: unknown;
}

export interface Approval {
  id?: string;
  status?: string;
  [key: string]: unknown;
}

/** The body of a `POST /v1/decide` response. */
export interface DecisionResponse {
  effect?: Effect;
  reason?: string;
  decision_id?: string | null;
  payload?: unknown;
  obligations?: Obligation[];
  classifications?: string[];
  redactions?: Redaction[];
  matched_policies?: string[];
  determining_policy?: string | null;
  unsupported_obligations?: string[];
  approval?: Approval | null;
  latency_ms?: number;
  approval_redeemed?: boolean;
  approval_error?: string | null;
  [key: string]: unknown;
}

export interface DecideOptions {
  principalId: string;
  action: string;
  principalType?: string;
  principalAttributes?: Record<string, unknown>;
  resourceUrn?: string;
  resourceKind?: string;
  classifications?: readonly string[];
  resourceAttributes?: Record<string, unknown>;
  context?: Record<string, unknown>;
  payload?: unknown;
  correlationId?: string;
  approvalId?: string;
  explain?: boolean;
  applyObligations?: boolean;
  /**
   * Whether to write a decision record. Leave it true unless you are asking a
   * question rather than taking an action -- deciding what to *offer* someone,
   * where nothing is carried out and the real decision happens later. An
   * enforcement point that acts on an answer must record it.
   */
  persist?: boolean;
  useCache?: boolean;
  /** Aborts the request. The client still fails closed if it fires. */
  signal?: AbortSignal;
}

export interface ClientOptions {
  apiKey?: string;
  /** Per-attempt timeout in milliseconds. */
  timeoutMs?: number;
  retries?: number;
  /** Deny when the control plane cannot be reached. Turn this off knowingly. */
  failClosed?: boolean;
  cacheTtlMs?: number;
  cacheMaxEntries?: number;
  defaultPrincipalType?: string;
  /** Injectable for tests and for runtimes with a non-global fetch. */
  fetch?: typeof globalThis.fetch;
}
