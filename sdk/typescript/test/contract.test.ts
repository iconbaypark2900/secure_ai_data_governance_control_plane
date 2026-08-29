/**
 * The two clients must put the same thing on the wire.
 *
 * test/contract.json is generated from the Python SDK's own `_build_body`, not
 * written by hand from the docs. Two clients that disagree about the request
 * body get different decisions out of the same policy, and the one that gets
 * used less is the one that stays wrong -- so this asserts equality against the
 * other implementation rather than against my reading of it.
 *
 * Regenerate with tools/generate_sdk_contract.py after changing either client.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { ControlPlaneClient } from "../src/client.js";
import { SATISFIED_BY_CONTROL_PLANE, Outcome, type DecideOptions } from "../src/types.js";
import { json, stubFetch } from "./helpers.js";

interface ContractCase {
  name: string;
  input: Record<string, unknown>;
  body: Record<string, unknown>;
  cache_key: string;
}

const contract = JSON.parse(
  readFileSync(fileURLToPath(new URL("./contract.json", import.meta.url)), "utf8"),
) as {
  cases: ContractCase[];
  satisfied_by_control_plane: string[];
  outcomes: string[];
};

/** snake_case in the fixture is the Python signature; the TS API is camelCase. */
const RENAMES: Record<string, string> = {
  principal_id: "principalId",
  principal_type: "principalType",
  principal_attributes: "principalAttributes",
  resource_urn: "resourceUrn",
  resource_kind: "resourceKind",
  resource_attributes: "resourceAttributes",
  correlation_id: "correlationId",
  approval_id: "approvalId",
  apply_obligations: "applyObligations",
};

function toOptions(input: Record<string, unknown>): DecideOptions {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    out[RENAMES[key] ?? key] = value;
  }
  return out as unknown as DecideOptions;
}

describe("the request body matches the Python SDK", () => {
  it.each(contract.cases.map((c) => [c.name, c] as const))("%s", async (_name, testCase) => {
    const { fetch, calls } = stubFetch({ responses: [json({ effect: "allow" })] });
    const client = new ControlPlaneClient("http://cp.test", { fetch, cacheTtlMs: 0 });
    await client.decide(toOptions(testCase.input));
    expect(calls[0]?.body).toEqual(testCase.body);
  });

  it("covers every field the body can carry", () => {
    const seen = new Set<string>();
    for (const testCase of contract.cases) {
      for (const key of Object.keys(testCase.body)) seen.add(key);
    }
    expect([...seen].sort()).toEqual([
      "action",
      "approval_id",
      "context",
      "correlation_id",
      "options",
      "payload",
      "principal",
      "resource",
    ]);
  });
});

describe("shared constants match the Python SDK", () => {
  it("agrees on which obligations the control plane already applied", () => {
    // Disagreeing here means one client refuses what the other permits, for a
    // decision both received identically.
    expect([...SATISFIED_BY_CONTROL_PLANE].sort()).toEqual(contract.satisfied_by_control_plane);
  });

  it("agrees on the outcome vocabulary", () => {
    expect([Outcome.ENFORCED, Outcome.REFUSED, Outcome.PARTIAL]).toEqual(contract.outcomes);
  });
});
