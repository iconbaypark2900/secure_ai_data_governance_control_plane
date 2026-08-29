/** A fetch stand-in, so tests exercise the client rather than a mock of it. */

export interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

export interface StubOptions {
  /** Respond to each call in turn; the last entry repeats. */
  responses?: Array<Response | (() => Response) | (() => Promise<Response>)>;
  /** Throw instead of responding, as a transport failure does. */
  throws?: () => never;
}

export function stubFetch(options: StubOptions = {}): {
  fetch: typeof globalThis.fetch;
  calls: Call[];
} {
  const calls: Call[] = [];
  const responses = options.responses ?? [json({ effect: "allow" })];

  const fetchImpl = (async (input: unknown, init?: RequestInit) => {
    calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: init?.body === undefined ? undefined : JSON.parse(String(init.body)),
    });
    if (options.throws) options.throws();
    const entry = responses[Math.min(calls.length - 1, responses.length - 1)];
    if (entry === undefined) throw new Error("no stub response");
    const result = await (typeof entry === "function" ? entry() : entry);
    // A Response body can be read once. Handing the same object back twice
    // makes the second read throw, which the client cannot tell from a
    // transport failure -- so it retries, and a test counting calls sees
    // numbers that look like a caching bug. Clone, and leave the original
    // unread.
    return result.clone();
  }) as unknown as typeof globalThis.fetch;

  return { fetch: fetchImpl, calls };
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export const ALLOW = {
  effect: "allow",
  reason: "permitted",
  decision_id: "d_1",
  payload: "clean text",
  obligations: [],
} as const;

export const DENY = {
  effect: "deny",
  reason: "'Credentials never move' produced 'deny'",
  decision_id: "d_2",
} as const;
