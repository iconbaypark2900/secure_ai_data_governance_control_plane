export { ControlPlaneClient } from "./client.js";
export type { AwaitApprovalOptions, OutcomeReport } from "./client.js";
export { Decision } from "./decision.js";
export {
  ApprovalTimeout,
  ControlPlaneError,
  ControlPlaneUnavailable,
  DecisionDenied,
  ObligationUnsatisfied,
} from "./errors.js";
export {
  Outcome,
  SATISFIED_BY_CONTROL_PLANE,
  TERMINAL_APPROVAL_STATES,
} from "./types.js";
export type {
  Approval,
  ClientOptions,
  DecideOptions,
  DecisionResponse,
  Effect,
  Obligation,
  OutcomeValue,
  Redaction,
} from "./types.js";

export const VERSION = "0.1.0";
