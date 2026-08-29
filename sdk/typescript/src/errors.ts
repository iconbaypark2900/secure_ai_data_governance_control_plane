/** Every error this client raises. */

import type { Decision } from "./decision.js";

export class ControlPlaneError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ControlPlaneError";
  }
}

/** The control plane could not be reached or did not answer in time. */
export class ControlPlaneUnavailable extends ControlPlaneError {
  constructor(message: string) {
    super(message);
    this.name = "ControlPlaneUnavailable";
  }
}

/** The requested action was refused. */
export class DecisionDenied extends ControlPlaneError {
  readonly decision: Decision;

  constructor(decision: Decision) {
    super(`denied: ${decision.reason}`);
    this.name = "DecisionDenied";
    this.decision = decision;
  }
}

/** A parked decision was not resolved within the time allowed. */
export class ApprovalTimeout extends ControlPlaneError {
  readonly approvalId: string;
  readonly waitedMs: number;

  constructor(approvalId: string, waitedMs: number) {
    super(`approval ${approvalId} was still unresolved after ${Math.round(waitedMs / 1000)}s`);
    this.name = "ApprovalTimeout";
    this.approvalId = approvalId;
    this.waitedMs = waitedMs;
  }
}

/**
 * An allow arrived carrying a duty this enforcement point cannot carry out.
 *
 * Raised rather than ignored on purpose: "allow, but redact the SSNs" must
 * never degrade into "allow".
 */
export class ObligationUnsatisfied extends ControlPlaneError {
  readonly decision: Decision;
  readonly obligations: readonly string[];

  constructor(decision: Decision, obligations: readonly string[]) {
    super(
      "the decision allows the action only subject to obligations this " +
        `enforcement point cannot satisfy: ${obligations.join(", ")}`,
    );
    this.name = "ObligationUnsatisfied";
    this.decision = decision;
    this.obligations = obligations;
  }
}
