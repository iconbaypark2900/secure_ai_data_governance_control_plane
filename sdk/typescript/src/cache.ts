/** A tiny TTL cache for payload-free decisions. */

import type { Decision } from "./decision.js";
import type { DecideOptions } from "./types.js";

export class DecisionCache {
  private readonly entries = new Map<string, { expiresAt: number; decision: Decision }>();

  constructor(
    private readonly ttlMs: number,
    private readonly maxEntries: number,
    private readonly now: () => number = () => Date.now(),
  ) {}

  get(key: string): Decision | null {
    const entry = this.entries.get(key);
    if (entry === undefined) return null;
    if (this.now() >= entry.expiresAt) {
      this.entries.delete(key);
      return null;
    }
    return entry.decision;
  }

  set(key: string, decision: Decision): void {
    if (this.ttlMs <= 0) return;
    if (this.entries.size >= this.maxEntries) {
      // Cheap eviction: drop the oldest insertion. A decision cache is a
      // latency optimisation, not a correctness mechanism, so an approximate
      // policy is fine. Map iterates in insertion order, so this is the oldest.
      const oldest = this.entries.keys().next();
      if (!oldest.done) this.entries.delete(oldest.value);
    }
    this.entries.set(key, { expiresAt: this.now() + this.ttlMs, decision });
  }

  clear(): void {
    this.entries.clear();
  }

  get size(): number {
    return this.entries.size;
  }
}

/** A stable, type-preserving rendering: sorted keys, no incidental whitespace. */
function canonical(value: unknown): string {
  const seen = new WeakSet<object>();
  const walk = (node: unknown): unknown => {
    if (node === null || typeof node !== "object") {
      return typeof node === "bigint" || typeof node === "function" ? String(node) : node;
    }
    if (seen.has(node)) return "[circular]";
    seen.add(node);
    if (Array.isArray(node)) return node.map(walk);
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(node as Record<string, unknown>).sort()) {
      out[key] = walk((node as Record<string, unknown>)[key]);
    }
    return out;
  };
  try {
    return JSON.stringify(walk(value)) ?? "null";
  } catch {
    return String(value);
  }
}

/**
 * The cache key.
 *
 * Context and classifications are JSON-encoded rather than stringified, which
 * is not cosmetic. The obvious `${k}=${v}` form conflates values the server
 * does not: it made `{external: true}` and `{external: "true"}` the same key,
 * and a policy matching a boolean does not match the string, so the second
 * caller would receive the first one's decision. The Python SDK had exactly
 * that bug, found by writing this function and asking what the two would
 * disagree about.
 *
 * Note what is absent: the payload. A decision about content depends on that
 * content, so a decision carrying one is never eligible at all -- see
 * `isCacheable`.
 *
 * These keys are not required to match the Python SDK's byte for byte, and do
 * not: the two languages format floats and escape non-ASCII differently. The
 * cache is process-local, so only internal consistency matters. What must match
 * across the two clients is the request *body*, which goes on the wire, and
 * that is asserted against a fixture generated from the Python SDK.
 */
export function cacheKey(options: DecideOptions, defaultPrincipalType: string): string {
  return [
    String(options.principalId),
    String(options.principalType ?? defaultPrincipalType),
    String(options.action),
    String(options.resourceUrn ?? "None"),
    canonical([...(options.classifications ?? [])].map(String).sort()),
    canonical(options.context ?? {}),
  ].join("|");
}

/**
 * Only the pure authorisation question is cacheable.
 *
 * A payload makes the decision content-dependent; an explain is a different
 * question with a different answer shape; an approval redemption is a state
 * change that must happen exactly once and would be spent twice if replayed
 * from a cache.
 */
export function isCacheable(options: DecideOptions): boolean {
  return (
    options.useCache !== false &&
    options.payload === undefined &&
    options.explain !== true &&
    options.approvalId === undefined
  );
}
