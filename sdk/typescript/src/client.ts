/**
 * The enforcement-point client.
 *
 * Three behaviours here are not conveniences but requirements of being an
 * enforcement point, and they are the reason to use this client rather than
 * calling the API directly:
 *
 * *Fail closed.* If the control plane cannot be reached, the client denies. An
 * enforcement point that lets traffic through when its authority is unavailable
 * provides no control at all -- it provides the appearance of one, which is
 * worse.
 *
 * *Obligations are binding.* A decision carrying an obligation the caller has
 * not declared it can satisfy is treated as a deny by `Decision.enforce`.
 * "Allow, but redact the SSNs" must never degrade into "allow".
 *
 * *Metadata-only caching.* Decisions with a payload are never cached, because
 * the payload is part of what was decided.
 *
 * This is a port of the Python SDK, not a reinterpretation of it. Where the two
 * could differ they do not: the request body, the cache key, what counts as
 * cacheable, and which obligations the control plane is taken to have already
 * applied are all the same, because two clients that disagree about any of them
 * get different decisions out of the same policy.
 */

import { DecisionCache, cacheKey, isCacheable } from "./cache.js";
import { Decision } from "./decision.js";
import {
  ApprovalTimeout,
  ControlPlaneError,
  ControlPlaneUnavailable,
  DecisionDenied,
  ObligationUnsatisfied,
} from "./errors.js";
import {
  Outcome,
  TERMINAL_APPROVAL_STATES,
  type ClientOptions,
  type DecideOptions,
  type DecisionResponse,
  type OutcomeValue,
} from "./types.js";

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_RETRIES = 2;
const DEFAULT_CACHE_TTL_MS = 5000;
const DEFAULT_CACHE_MAX_ENTRIES = 1024;

export interface OutcomeReport {
  reason?: string;
  discharged?: Iterable<string>;
  undischarged?: Iterable<string>;
}

export interface AwaitApprovalOptions {
  timeoutMs?: number;
  pollIntervalMs?: number;
  signal?: AbortSignal;
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}

export class ControlPlaneClient {
  readonly baseUrl: string;
  readonly defaultPrincipalType: string;
  private readonly apiKey: string | undefined;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly failClosed: boolean;
  private readonly cache: DecisionCache;
  private readonly fetchImpl: typeof globalThis.fetch;

  constructor(baseUrl: string, options: ClientOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.retries = Math.max(0, options.retries ?? DEFAULT_RETRIES);
    this.failClosed = options.failClosed ?? true;
    this.defaultPrincipalType = options.defaultPrincipalType ?? "service";
    this.cache = new DecisionCache(
      options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS,
      options.cacheMaxEntries ?? DEFAULT_CACHE_MAX_ENTRIES,
    );
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    if (typeof this.fetchImpl !== "function") {
      throw new TypeError("no fetch available; pass one as options.fetch");
    }
  }

  private headers(): Record<string, string> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.apiKey) headers["X-API-Key"] = this.apiKey;
    return headers;
  }

  clearCache(): void {
    this.cache.clear();
  }

  /** Ask whether an action is permitted. */
  async decide(options: DecideOptions): Promise<Decision> {
    const body = this.buildBody(options);
    const cacheable = isCacheable(options);
    const key = cacheable ? cacheKey(options, this.defaultPrincipalType) : "";
    if (cacheable) {
      const cached = this.cache.get(key);
      if (cached !== null) return cached;
    }

    let lastError: unknown = null;
    for (let attempt = 0; attempt <= this.retries; attempt += 1) {
      try {
        const response = await this.request("POST", "/v1/decide", body, options.signal);
        const decision = await this.handle(response);
        if (cacheable) this.cache.set(key, decision);
        return decision;
      } catch (error) {
        if (error instanceof ControlPlaneError) throw error;
        lastError = error;
        // A caller-supplied abort is a decision by the caller, not a transport
        // failure. Retrying it would ignore what they asked for.
        if (options.signal?.aborted) break;
        if (attempt < this.retries) {
          // Linear backoff: the control plane is on the request path, so a long
          // exponential wait costs more than failing fast.
          await sleep(50 * (attempt + 1));
        }
      }
    }
    return this.onUnreachable(lastError);
  }

  /** Classify a payload without asking for a decision about it. */
  async classify(payload: unknown, minConfidence = 0): Promise<Record<string, unknown>> {
    const response = await this.request("POST", "/v1/classify", {
      payload,
      min_confidence: minConfidence,
    });
    if (!response.ok) {
      throw new ControlPlaneError(
        `control plane returned ${response.status}: ${await detail(response)}`,
      );
    }
    return (await response.json()) as Record<string, unknown>;
  }

  /**
   * Tell the control plane what actually happened.
   *
   * Never throws. By the time this is called the action has already been taken
   * or refused, and failing the caller over a bookkeeping round trip would turn
   * a reporting problem into an outage. An outcome that does not arrive shows
   * up server-side as *unreported*, which is the detection path -- silence is
   * treated as "nothing is known", not as "it went fine".
   */
  async reportOutcome(
    decision: Decision,
    outcome: OutcomeValue,
    report: OutcomeReport = {},
  ): Promise<boolean> {
    if (!decision.decisionId) return false;
    try {
      const response = await this.request("POST", `/v1/decisions/${decision.decisionId}/outcome`, {
        outcome,
        reason: report.reason ?? "",
        discharged: [...new Set(report.discharged ?? [])].sort(),
        undischarged: [...new Set(report.undischarged ?? [])].sort(),
      });
      return response.status < 300;
    } catch {
      return false;
    }
  }

  /**
   * Act on a decision, and report the outcome when the work is done.
   *
   * The right shape whenever anything happens *after* the obligation check -- a
   * backend call, a downstream hop, a second decision. Reporting at the moment
   * the obligations merely check out is premature: the action has not happened
   * yet, and if a later step fails the record ends up saying "enforced" behind
   * something that never took place.
   *
   * ```ts
   * await client.enforcing(decision, async (payload) => {
   *   await sendUpstream(payload);
   * }, { canSatisfy: ["watermark"] });
   * ```
   *
   * JavaScript has no `with`, so this takes the work as a callback. That is not
   * only a translation detail -- it is what makes the reporting unskippable,
   * since there is no way to obtain the payload without also handing over the
   * work that uses it.
   *
   * A throw from the callback is reported as a refusal, because from the
   * control plane's side that is what it is: permitted, and it did not happen.
   * So is an obligation this point cannot discharge, which is the same refusal
   * arriving earlier -- reporting one and not the other left the decision
   * *unreported*, and a duty nobody could carry out is exactly what an operator
   * is scanning that list for.
   *
   * A denial is not reported: nothing was permitted, so there is no action to
   * account for, and the record already says it was refused.
   */
  async enforcing<T>(
    decision: Decision,
    work: (payload: unknown) => T | Promise<T>,
    options: { canSatisfy?: Iterable<string> } = {},
  ): Promise<T> {
    let payload: unknown;
    try {
      payload = decision.enforce(options.canSatisfy ?? []);
    } catch (error) {
      if (error instanceof ObligationUnsatisfied) {
        const missing = new Set(error.obligations);
        await this.reportOutcome(decision, Outcome.REFUSED, {
          reason: error.message,
          discharged: decision.obligationTypes().filter((type) => !missing.has(type)),
          undischarged: error.obligations,
        });
      }
      throw error;
    }
    let result: T;
    try {
      result = await work(payload);
    } catch (error) {
      await this.reportOutcome(decision, Outcome.REFUSED, {
        reason: errorMessage(error),
        discharged: [],
        undischarged: decision.obligationTypes(),
      });
      throw error;
    }
    await this.reportOutcome(decision, Outcome.ENFORCED, {
      discharged: decision.obligationTypes(),
    });
    return result;
  }

  /**
   * Act on a decision and report it enforced, in one call.
   *
   * Correct only when acting on the decision is the *last* thing that happens.
   * If anything can still fail afterwards, use `enforcing`: this reports
   * success as soon as the obligations check out, and a later failure would
   * leave a record saying "enforced" behind an action that never took place.
   */
  async enforce(decision: Decision, canSatisfy: Iterable<string> = []): Promise<unknown> {
    let payload: unknown;
    try {
      payload = decision.enforce(canSatisfy);
    } catch (error) {
      if (error instanceof ObligationUnsatisfied) {
        const missing = new Set(error.obligations);
        await this.reportOutcome(decision, Outcome.REFUSED, {
          reason: error.message,
          discharged: decision.obligationTypes().filter((type) => !missing.has(type)),
          undischarged: error.obligations,
        });
      }
      // A DecisionDenied needs no report: the record already says it was
      // refused, and the enforcement point never had an action to take.
      throw error;
    }
    await this.reportOutcome(decision, Outcome.ENFORCED, {
      discharged: decision.obligationTypes(),
    });
    return payload;
  }

  /**
   * Report that the action happened but a duty went undischarged.
   *
   * The honest outcome when an enforcement point proceeds anyway. Reporting
   * `enforced` here would hide the very thing worth knowing.
   */
  async reportPartial(
    decision: Decision,
    undischarged: Iterable<string>,
    reason: string,
  ): Promise<boolean> {
    const missing = [...new Set(undischarged)].sort();
    const missingSet = new Set(missing);
    return this.reportOutcome(decision, Outcome.PARTIAL, {
      reason,
      discharged: decision.obligationTypes().filter((type) => !missingSet.has(type)),
      undischarged: missing,
    });
  }

  /** Read the current state of a parked decision. */
  async getApproval(approvalId: string): Promise<Record<string, unknown>> {
    const response = await this.request("GET", `/v1/approvals/${approvalId}`);
    if (!response.ok) {
      throw new ControlPlaneError(
        `control plane returned ${response.status}: ${await detail(response)}`,
      );
    }
    return (await response.json()) as Record<string, unknown>;
  }

  /**
   * Poll until a human resolves the request, then return it.
   *
   * Polls the approvals endpoint rather than re-sending the decision: that is a
   * cheap read, and it does not evaluate policy, write a decision record, and
   * seal an audit entry every couple of seconds.
   *
   * Returns on any terminal state -- granted, denied, or expired -- so the
   * caller decides what to do about a refusal.
   */
  async awaitApproval(
    approvalId: string,
    options: AwaitApprovalOptions = {},
  ): Promise<Record<string, unknown>> {
    const timeoutMs = options.timeoutMs ?? 300_000;
    const pollIntervalMs = options.pollIntervalMs ?? 2000;
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const approval = await this.getApproval(approvalId);
      if (TERMINAL_APPROVAL_STATES.has(String(approval["status"]))) return approval;
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new ApprovalTimeout(approvalId, timeoutMs);
      if (options.signal?.aborted) throw new ApprovalTimeout(approvalId, timeoutMs);
      await sleep(Math.min(pollIntervalMs, remaining));
    }
  }

  async health(): Promise<boolean> {
    try {
      const response = await this.request("GET", "/v1/health");
      return response.status === 200;
    } catch {
      return false;
    }
  }

  private buildBody(options: DecideOptions): Record<string, unknown> {
    const body: Record<string, unknown> = {
      principal: {
        id: options.principalId,
        type: options.principalType ?? this.defaultPrincipalType,
        attributes: { ...(options.principalAttributes ?? {}) },
      },
      action: options.action,
      resource: {
        urn: options.resourceUrn ?? null,
        kind: options.resourceKind ?? null,
        classifications: [...(options.classifications ?? [])],
        attributes: { ...(options.resourceAttributes ?? {}) },
      },
      context: { ...(options.context ?? {}) },
      options: {
        explain: options.explain ?? false,
        apply_obligations: options.applyObligations ?? true,
        persist: options.persist ?? true,
      },
    };
    if (options.payload !== undefined) body["payload"] = options.payload;
    if (options.correlationId) body["correlation_id"] = options.correlationId;
    if (options.approvalId) body["approval_id"] = String(options.approvalId);
    return body;
  }

  private async request(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
    signal?: AbortSignal,
  ): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const onAbort = (): void => controller.abort();
    signal?.addEventListener("abort", onAbort, { once: true });
    try {
      return await this.fetchImpl(`${this.baseUrl}${path}`, {
        method,
        headers: this.headers(),
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    }
  }

  private async handle(response: Response): Promise<Decision> {
    if (response.status === 200) {
      return Decision.fromResponse((await response.json()) as DecisionResponse);
    }
    if (response.status === 401 || response.status === 403) {
      // An authorisation failure against the control plane is itself a denial,
      // not a reason to proceed unchecked.
      return Decision.denial(
        `the control plane rejected this enforcement point ` +
          `(${response.status}): ${await detail(response)}`,
      );
    }
    throw new ControlPlaneError(
      `control plane returned ${response.status}: ${await detail(response)}`,
    );
  }

  private onUnreachable(error: unknown): Decision {
    const message = isAbortError(error) ? "the request timed out" : errorMessage(error);
    if (this.failClosed) {
      return Decision.denial(
        `the control plane is unreachable and this enforcement point fails closed: ${message}`,
      );
    }
    throw new ControlPlaneUnavailable(message);
  }
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message || error.name;
  return String(error);
}

async function detail(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: unknown };
    return String(body.detail ?? "").slice(0, 500);
  } catch {
    return `HTTP ${response.status}`;
  }
}

export { Decision, DecisionDenied, ObligationUnsatisfied, ControlPlaneUnavailable, ApprovalTimeout };
