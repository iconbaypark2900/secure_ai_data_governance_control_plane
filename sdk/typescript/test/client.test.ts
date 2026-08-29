/**
 * What makes this an enforcement-point client rather than an HTTP wrapper.
 *
 * Each block here is a property the Python SDK's docstring calls a requirement
 * rather than a convenience. A port that got the request body right and these
 * wrong would be worse than no port at all: it would look correct.
 */

import { describe, expect, it, vi } from "vitest";

import { ControlPlaneClient } from "../src/client.js";
import { Decision } from "../src/decision.js";
import {
  ApprovalTimeout,
  ControlPlaneError,
  ControlPlaneUnavailable,
  DecisionDenied,
  ObligationUnsatisfied,
} from "../src/errors.js";
import { Outcome } from "../src/types.js";
import { ALLOW, DENY, json, stubFetch } from "./helpers.js";

describe("it fails closed", () => {
  it("denies when the control plane cannot be reached", async () => {
    const { fetch } = stubFetch({
      throws: () => {
        throw new TypeError("fetch failed");
      },
    });
    const client = new ControlPlaneClient("http://cp.test", { fetch, retries: 0 });
    const decision = await client.decide({ principalId: "a", action: "read" });
    // Not an exception the caller might catch and shrug off. A denial.
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("fails closed");
  });

  it("retries a transport failure before giving up", async () => {
    let attempts = 0;
    const fetchImpl = (async () => {
      attempts += 1;
      if (attempts < 3) throw new TypeError("connection reset");
      return json(ALLOW);
    }) as unknown as typeof globalThis.fetch;
    const client = new ControlPlaneClient("http://cp.test", { fetch: fetchImpl, retries: 2 });
    const decision = await client.decide({ principalId: "a", action: "read" });
    expect(attempts).toBe(3);
    expect(decision.allowed).toBe(true);
  });

  it("raises instead of denying only when told to fail open", async () => {
    const { fetch } = stubFetch({
      throws: () => {
        throw new TypeError("fetch failed");
      },
    });
    const client = new ControlPlaneClient("http://cp.test", {
      fetch,
      retries: 0,
      failClosed: false,
    });
    await expect(client.decide({ principalId: "a", action: "read" })).rejects.toBeInstanceOf(
      ControlPlaneUnavailable,
    );
  });

  it.each([401, 403])("treats %i from the control plane as a denial", async (status) => {
    const { fetch } = stubFetch({ responses: [json({ detail: "bad key" }, status)] });
    const client = new ControlPlaneClient("http://cp.test", { fetch });
    const decision = await client.decide({ principalId: "a", action: "read" });
    // Our own credentials being wrong is not a reason to proceed unchecked.
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("rejected this enforcement point");
  });

  it("surfaces a server error rather than silently denying", async () => {
    // A 500 is a fault, not a verdict. Turning it into a deny would hide an
    // outage behind a plausible-looking refusal.
    const { fetch } = stubFetch({ responses: [json({ detail: "boom" }, 500)] });
    const client = new ControlPlaneClient("http://cp.test", { fetch, retries: 0 });
    await expect(client.decide({ principalId: "a", action: "read" })).rejects.toBeInstanceOf(
      ControlPlaneError,
    );
  });
});

describe("obligations are binding", () => {
  const withObligation = {
    ...ALLOW,
    obligations: [{ type: "watermark", text: "internal" }, { type: "log", level: "info" }],
  };

  it("an undeclared obligation turns an allow into a refusal", async () => {
    const { fetch } = stubFetch({ responses: [json(withObligation)] });
    const client = new ControlPlaneClient("http://cp.test", { fetch });
    const decision = await client.decide({ principalId: "a", action: "read" });
    expect(decision.allowed).toBe(true);
    expect(() => decision.enforce()).toThrowError(ObligationUnsatisfied);
  });

  it("declaring it lets the action proceed", async () => {
    const { fetch } = stubFetch({ responses: [json(withObligation)] });
    const client = new ControlPlaneClient("http://cp.test", { fetch });
    const decision = await client.decide({ principalId: "a", action: "read" });
    expect(decision.enforce(["watermark"])).toBe("clean text");
  });

  it("obligations the control plane already applied need no declaration", () => {
    const decision = Decision.fromResponse({
      effect: "allow",
      payload: "redacted",
      obligations: [{ type: "redact" }, { type: "annotate" }, { type: "ttl" }],
    });
    expect(decision.outstanding()).toEqual([]);
  });

  it("a denial raises before obligations are even considered", () => {
    const decision = Decision.fromResponse({ ...DENY, obligations: [{ type: "watermark" }] });
    expect(() => decision.enforce(["watermark"])).toThrowError(DecisionDenied);
  });
});

describe("only the pure authorisation question is cached", () => {
  it("repeats the same question from cache", async () => {
    const { fetch, calls } = stubFetch({ responses: [json(ALLOW)] });
    const client = new ControlPlaneClient("http://cp.test", { fetch, cacheTtlMs: 60_000 });
    await client.decide({ principalId: "a", action: "read", resourceUrn: "r" });
    await client.decide({ principalId: "a", action: "read", resourceUrn: "r" });
    expect(calls).toHaveLength(1);
  });

  it("never caches a decision about content", async () => {
    // The payload is part of what was decided, so it cannot be reused.
    const { fetch, calls } = stubFetch({ responses: [json(ALLOW)] });
    const client = new ControlPlaneClient("http://cp.test", { fetch, cacheTtlMs: 60_000 });
    for (const text of ["harmless", "ssn 536-90-4432", "harmless"]) {
      await client.decide({ principalId: "a", action: "read", payload: text });
    }
    expect(calls).toHaveLength(3);
  });

  it("never caches an approval redemption", async () => {
    // A redemption is a state change that must happen exactly once.
    const { fetch, calls } = stubFetch({ responses: [json(ALLOW)] });
    const client = new ControlPlaneClient("http://cp.test", { fetch, cacheTtlMs: 60_000 });
    await client.decide({ principalId: "a", action: "read", approvalId: "ap_1" });
    await client.decide({ principalId: "a", action: "read", approvalId: "ap_1" });
    expect(calls).toHaveLength(2);
  });

  it("never caches an explain", async () => {
    const { fetch, calls } = stubFetch({ responses: [json(ALLOW)] });
    const client = new ControlPlaneClient("http://cp.test", { fetch, cacheTtlMs: 60_000 });
    await client.decide({ principalId: "a", action: "read", explain: true });
    await client.decide({ principalId: "a", action: "read", explain: true });
    expect(calls).toHaveLength(2);
  });

  it.each([
    [{ external: true }, { external: "True" }],
    [{ limit: 1 }, { limit: "1" }],
    [{ region: null }, { region: "None" }],
  ])("distinguishes context values of different types", async (first, second) => {
    // The bug this port found in the Python SDK: a key built by stringifying
    // each value conflates things the policy engine does not, so the second
    // caller receives the first one's decision.
    const { fetch, calls } = stubFetch({ responses: [json(ALLOW)] });
    const client = new ControlPlaneClient("http://cp.test", { fetch, cacheTtlMs: 60_000 });
    await client.decide({ principalId: "a", action: "read", context: first });
    await client.decide({ principalId: "a", action: "read", context: second });
    expect(calls).toHaveLength(2);
  });

  it("distinguishes a classification containing the separator", async () => {
    const { fetch, calls } = stubFetch({ responses: [json(ALLOW)] });
    const client = new ControlPlaneClient("http://cp.test", { fetch, cacheTtlMs: 60_000 });
    await client.decide({ principalId: "a", action: "read", classifications: ["a,b"] });
    await client.decide({ principalId: "a", action: "read", classifications: ["a", "b"] });
    expect(calls).toHaveLength(2);
  });

  it("still hits whatever order the context keys came in", async () => {
    const { fetch, calls } = stubFetch({ responses: [json(ALLOW)] });
    const client = new ControlPlaneClient("http://cp.test", { fetch, cacheTtlMs: 60_000 });
    await client.decide({ principalId: "a", action: "read", context: { a: 1, b: true } });
    await client.decide({ principalId: "a", action: "read", context: { b: true, a: 1 } });
    expect(calls).toHaveLength(1);
  });
});

describe("outcomes are reported", () => {
  it("reports enforced only after the work has finished", async () => {
    const order: string[] = [];
    const { fetch, calls } = stubFetch({ responses: [json(ALLOW), json({})] });
    const client = new ControlPlaneClient("http://cp.test", { fetch });
    const decision = await client.decide({ principalId: "a", action: "read" });
    await client.enforcing(decision, async () => {
      order.push("work");
      // Reporting before this point would record "enforced" behind an action
      // that had not happened yet.
      expect(calls).toHaveLength(1);
    });
    order.push("reported");
    expect(order).toEqual(["work", "reported"]);
    expect(calls[1]?.url).toBe("http://cp.test/v1/decisions/d_1/outcome");
    expect(calls[1]?.body).toMatchObject({ outcome: Outcome.ENFORCED });
  });

  it("reports refused when the work throws, and rethrows", async () => {
    const { fetch, calls } = stubFetch({ responses: [json(ALLOW), json({})] });
    const client = new ControlPlaneClient("http://cp.test", { fetch });
    const decision = await client.decide({ principalId: "a", action: "read" });
    await expect(
      client.enforcing(decision, () => {
        throw new Error("upstream refused");
      }),
    ).rejects.toThrowError("upstream refused");
    expect(calls[1]?.body).toMatchObject({
      outcome: Outcome.REFUSED,
      reason: "upstream refused",
    });
  });

  it("returns what the work returned", async () => {
    const { fetch } = stubFetch({ responses: [json(ALLOW), json({})] });
    const client = new ControlPlaneClient("http://cp.test", { fetch });
    const decision = await client.decide({ principalId: "a", action: "read" });
    const result = await client.enforcing(decision, (payload) => `sent: ${String(payload)}`);
    expect(result).toBe("sent: clean text");
  });

  it("reports nothing and does no work when the decision was a denial", async () => {
    const { fetch, calls } = stubFetch({ responses: [json(DENY)] });
    const client = new ControlPlaneClient("http://cp.test", { fetch });
    const decision = await client.decide({ principalId: "a", action: "read" });
    const work = vi.fn();
    await expect(client.enforcing(decision, work)).rejects.toBeInstanceOf(DecisionDenied);
    expect(work).not.toHaveBeenCalled();
    // The record already says refused; there is no action to account for.
    expect(calls).toHaveLength(1);
  });

  it("reports refused with the undischarged duties when it cannot satisfy one", async () => {
    const { fetch, calls } = stubFetch({
      responses: [json({ ...ALLOW, obligations: [{ type: "watermark" }, { type: "log" }] }), json({})],
    });
    const client = new ControlPlaneClient("http://cp.test", { fetch });
    const decision = await client.decide({ principalId: "a", action: "read" });
    await expect(client.enforce(decision)).rejects.toBeInstanceOf(ObligationUnsatisfied);
    expect(calls[1]?.body).toMatchObject({
      outcome: Outcome.REFUSED,
      discharged: ["log"],
      undischarged: ["watermark"],
    });
  });

  it("partial names what went undischarged", async () => {
    const { fetch, calls } = stubFetch({
      responses: [json({ ...ALLOW, obligations: [{ type: "watermark" }, { type: "limit" }] }), json({})],
    });
    const client = new ControlPlaneClient("http://cp.test", { fetch });
    const decision = await client.decide({ principalId: "a", action: "read" });
    await client.reportPartial(decision, ["watermark"], "no watermarker configured");
    expect(calls[1]?.body).toMatchObject({
      outcome: Outcome.PARTIAL,
      discharged: ["limit"],
      undischarged: ["watermark"],
    });
  });

  it("never fails the caller over a reporting round trip", async () => {
    // By now the action has already happened. Turning a bookkeeping failure
    // into an exception would turn it into an outage.
    let call = 0;
    const fetchImpl = (async () => {
      call += 1;
      if (call === 1) return json(ALLOW);
      throw new TypeError("reporting endpoint down");
    }) as unknown as typeof globalThis.fetch;
    const client = new ControlPlaneClient("http://cp.test", { fetch: fetchImpl });
    const decision = await client.decide({ principalId: "a", action: "read" });
    await expect(client.enforcing(decision, () => "done")).resolves.toBe("done");
  });

  it("mirrors Python by NOT reporting when enforcing() cannot satisfy a duty", async () => {
    // Deliberately pinned, and worth flagging rather than presenting as design.
    // client.enforce() reports "refused" when an obligation cannot be
    // discharged; client.enforcing() throws from decision.enforce() before its
    // try block and reports nothing, so the decision stays *unreported* -- the
    // state the outcome work exists to make visible. The Python SDK behaves the
    // same way, and a port that quietly diverged would be the worse of the two
    // problems. If Python changes, change this with it.
    const { fetch, calls } = stubFetch({
      responses: [json({ ...ALLOW, obligations: [{ type: "watermark" }] })],
    });
    const client = new ControlPlaneClient("http://cp.test", { fetch });
    const decision = await client.decide({ principalId: "a", action: "read" });
    await expect(client.enforcing(decision, () => "x")).rejects.toBeInstanceOf(
      ObligationUnsatisfied,
    );
    expect(calls).toHaveLength(1);
  });

  it("reports nothing for a decision that was never recorded", async () => {
    // A client-side denial has no decision_id; there is nothing to report to.
    const client = new ControlPlaneClient("http://cp.test", { fetch: stubFetch().fetch });
    expect(await client.reportOutcome(Decision.denial("unreachable"), Outcome.REFUSED)).toBe(false);
  });
});

describe("approvals", () => {
  it("returns on any terminal state, so the caller decides about a refusal", async () => {
    const { fetch } = stubFetch({
      responses: [json({ id: "ap_1", status: "pending" }), json({ id: "ap_1", status: "denied" })],
    });
    const client = new ControlPlaneClient("http://cp.test", { fetch });
    const approval = await client.awaitApproval("ap_1", { pollIntervalMs: 1 });
    expect(approval["status"]).toBe("denied");
  });

  it("times out rather than polling forever", async () => {
    const { fetch } = stubFetch({ responses: [json({ id: "ap_1", status: "pending" })] });
    const client = new ControlPlaneClient("http://cp.test", { fetch });
    await expect(
      client.awaitApproval("ap_1", { timeoutMs: 5, pollIntervalMs: 1 }),
    ).rejects.toBeInstanceOf(ApprovalTimeout);
  });
});

describe("the api key travels", () => {
  it("is sent as X-API-Key", async () => {
    const { fetch, calls } = stubFetch({ responses: [json(ALLOW)] });
    const client = new ControlPlaneClient("http://cp.test", { fetch, apiKey: "cpk_test" });
    await client.decide({ principalId: "a", action: "read" });
    expect(calls[0]?.headers["X-API-Key"]).toBe("cpk_test");
  });

  it("is absent when none was configured", async () => {
    const { fetch, calls } = stubFetch({ responses: [json(ALLOW)] });
    const client = new ControlPlaneClient("http://cp.test", { fetch });
    await client.decide({ principalId: "a", action: "read" });
    expect(calls[0]?.headers["X-API-Key"]).toBeUndefined();
  });
});
