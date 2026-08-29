/** A decision as seen by the enforcement point. */

import { DecisionDenied, ObligationUnsatisfied } from "./errors.js";
import {
  SATISFIED_BY_CONTROL_PLANE,
  type Approval,
  type DecisionResponse,
  type Effect,
  type Obligation,
  type Redaction,
} from "./types.js";

export class Decision {
  readonly effect: Effect;
  readonly reason: string;
  readonly decisionId: string | null;
  readonly payload: unknown;
  readonly obligations: readonly Obligation[];
  readonly classifications: readonly string[];
  readonly redactions: readonly Redaction[];
  readonly matchedPolicies: readonly string[];
  readonly determiningPolicy: string | null;
  readonly unsupportedObligations: readonly string[];
  readonly approval: Approval | null;
  readonly latencyMs: number;
  /** The response verbatim, for anything this class does not model. */
  readonly raw: DecisionResponse;

  private constructor(body: DecisionResponse) {
    this.effect = body.effect ?? "deny";
    this.reason = body.reason ?? "";
    this.decisionId = body.decision_id ?? null;
    this.payload = body.payload;
    this.obligations = Object.freeze([...(body.obligations ?? [])]);
    this.classifications = Object.freeze([...(body.classifications ?? [])]);
    this.redactions = Object.freeze([...(body.redactions ?? [])]);
    this.matchedPolicies = Object.freeze([...(body.matched_policies ?? [])]);
    this.determiningPolicy = body.determining_policy ?? null;
    this.unsupportedObligations = Object.freeze([...(body.unsupported_obligations ?? [])]);
    this.approval = body.approval ?? null;
    this.latencyMs = Number(body.latency_ms ?? 0);
    this.raw = body;
    Object.freeze(this);
  }

  static fromResponse(body: DecisionResponse): Decision {
    return new Decision(body);
  }

  /** A denial this client produced itself, with no decision record behind it. */
  static denial(reason: string): Decision {
    return new Decision({ effect: "deny", reason });
  }

  get allowed(): boolean {
    return this.effect === "allow";
  }

  get needsApproval(): boolean {
    return this.effect === "require_approval";
  }

  /** The approval to wait on, when this decision was parked for a human. */
  get approvalId(): string | null {
    return this.approval?.id ?? null;
  }

  get approvalRedeemed(): boolean {
    return Boolean(this.raw.approval_redeemed);
  }

  /** Why a presented approval did not apply, if one was presented. */
  get approvalError(): string | null {
    const error = this.raw.approval_error;
    return error ? String(error) : null;
  }

  get redacted(): boolean {
    return this.redactions.length > 0;
  }

  obligationTypes(): string[] {
    const types = new Set<string>();
    for (const obligation of this.obligations) {
      if (obligation.type) types.add(String(obligation.type));
    }
    return [...types].sort();
  }

  /** Obligation types nobody in this exchange is going to carry out. */
  outstanding(canSatisfy: Iterable<string> = []): string[] {
    const satisfiable = new Set([...SATISFIED_BY_CONTROL_PLANE, ...canSatisfy].map(String));
    return this.obligationTypes().filter((type) => !satisfiable.has(type));
  }

  /**
   * Return the payload, or throw if the action must not proceed.
   *
   * `canSatisfy` names obligation types this enforcement point implements
   * itself. Anything the control plane did not already apply, and that is not
   * named here, turns the allow into a refusal.
   *
   * Pure: it decides, it does not report. Use the client's `enforcing` to have
   * the outcome reported too, which is what makes the control plane's record
   * match what happened.
   */
  enforce(canSatisfy: Iterable<string> = []): unknown {
    if (!this.allowed) throw new DecisionDenied(this);
    const outstanding = this.outstanding(canSatisfy);
    if (outstanding.length > 0) throw new ObligationUnsatisfied(this, outstanding);
    return this.payload;
  }
}
