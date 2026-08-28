import { useState } from "react";
import { api, type DecideResponse } from "../lib/api";
import { Banner, EffectPill, FindingsTable, LabelTag } from "../components/atoms";
import { Trace } from "../components/Trace";

const EXAMPLES: { title: string; body: Form }[] = [
  {
    title: "Agent reads the knowledge base",
    body: {
      principalId: "agent:support_bot", principalType: "agent", action: "read",
      resourceUrn: "qdrant://kb_docs", destination: "internal", purpose: "support",
      payload: "Customer jane.doe@acme.com (SSN 536-90-4432) asks about refunds.",
    },
  },
  {
    title: "Health data to an external model",
    body: {
      principalId: "agent:analytics_copilot", principalType: "agent", action: "infer",
      resourceUrn: "pg://clinical.encounters", destination: "external", purpose: "analysis",
      payload: "",
    },
  },
  {
    title: "A credential in the prompt",
    body: {
      principalId: "user:analyst", principalType: "user", action: "read",
      resourceUrn: "qdrant://kb_docs", destination: "internal", purpose: "debug",
      payload: "deploy with AKIAIOSFODNN7EXAMPLE",
    },
  },
  {
    title: "Bulk export of customers",
    body: {
      principalId: "user:analyst", principalType: "user", action: "export",
      resourceUrn: "pg://public.customers", destination: "internal", purpose: "reporting",
      payload: "",
    },
  },
];

interface Form {
  principalId: string; principalType: string; action: string;
  resourceUrn: string; destination: string; purpose: string; payload: string;
}

const EMPTY: Form = {
  principalId: "agent:support_bot", principalType: "agent", action: "read",
  resourceUrn: "qdrant://kb_docs", destination: "internal", purpose: "support", payload: "",
};

export function Simulator() {
  const [form, setForm] = useState<Form>(EXAMPLES[0]!.body);
  const [result, setResult] = useState<DecideResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function update<K extends keyof Form>(key: K, value: Form[K]) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  async function run() {
    setBusy(true);
    setError(null);
    try {
      // Simulation never persists: it must be safe to explore a policy change
      // without polluting the decision record or the audit chain.
      const response = await api.simulate({
        request: {
          principal: { id: form.principalId, type: form.principalType },
          action: form.action,
          resource: { urn: form.resourceUrn || null },
          context: { destination: form.destination, purpose: form.purpose },
          payload: form.payload || null,
          options: { explain: true, persist: false },
        },
      });
      setResult(response.decision);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="page-head">
        <h1>Simulator</h1>
        <p>
          Ask the policy engine a question and see the full reasoning. Nothing here is
          recorded or enforced, so it is safe to explore a change before making it.
        </p>
      </div>

      <div className="card">
        <div className="row" style={{ marginBottom: 12 }}>
          {EXAMPLES.map((example) => (
            <button key={example.title} onClick={() => { setForm(example.body); setResult(null); }}>
              {example.title}
            </button>
          ))}
          <button onClick={() => { setForm(EMPTY); setResult(null); }}>Clear</button>
        </div>

        <div className="grid cols-2">
          <div>
            <div className="field">
              <label>Principal</label>
              <input value={form.principalId}
                onChange={(event) => update("principalId", event.target.value)} />
            </div>
            <div className="field">
              <label>Principal type</label>
              <select value={form.principalType}
                onChange={(event) => update("principalType", event.target.value)}>
                <option>agent</option><option>user</option>
                <option>service</option><option>unknown</option>
              </select>
            </div>
            <div className="field">
              <label>Action</label>
              <input value={form.action}
                onChange={(event) => update("action", event.target.value)} />
            </div>
          </div>
          <div>
            <div className="field">
              <label>Resource URN</label>
              <input value={form.resourceUrn}
                onChange={(event) => update("resourceUrn", event.target.value)} />
            </div>
            <div className="field">
              <label>Destination</label>
              <select value={form.destination}
                onChange={(event) => update("destination", event.target.value)}>
                <option>internal</option><option>external</option>
              </select>
            </div>
            <div className="field">
              <label>Purpose</label>
              <input value={form.purpose}
                onChange={(event) => update("purpose", event.target.value)} />
            </div>
          </div>
        </div>

        <div className="field">
          <label>Payload — classified in memory, never stored</label>
          <textarea rows={4} value={form.payload}
            onChange={(event) => update("payload", event.target.value)} />
        </div>

        <button className="primary" onClick={run} disabled={busy}>
          {busy ? "Evaluating…" : "Evaluate"}
        </button>
      </div>

      {error && <Banner kind="error">{error}</Banner>}

      {result && (
        <>
          <div className="card">
            <div className="spread">
              <div className="row">
                <EffectPill effect={result.effect} />
                <strong>{result.determining_policy ?? "no policy matched"}</strong>
              </div>
              <span className="small dim">{result.latency_ms.toFixed(1)} ms</span>
            </div>
            <p className="dim">{result.reason}</p>

            {result.classifications.length > 0 && (
              <p>
                <span className="small dim">labels: </span>
                {result.classifications.map((key) => <LabelTag key={key} label={key} />)}
              </p>
            )}
            {result.regulations.length > 0 && (
              <p className="small dim">implicates {result.regulations.join(", ")}</p>
            )}
            {result.obligations.length > 0 && (
              <>
                <h2>Obligations</h2>
                <pre>{JSON.stringify(result.obligations, null, 2)}</pre>
              </>
            )}
            {result.payload !== null && result.payload !== undefined && (
              <>
                <h2>Governed payload</h2>
                <pre>{typeof result.payload === "string"
                  ? result.payload
                  : JSON.stringify(result.payload, null, 2)}</pre>
              </>
            )}
            {result.effect === "deny" && form.payload && (
              <p className="small dim">
                No payload is returned on a deny — a refusal that echoes the data it
                refused is not a refusal.
              </p>
            )}
          </div>

          {result.findings.length > 0 && (
            <div className="card">
              <h2>What the classifier found</h2>
              <FindingsTable findings={result.findings} />
            </div>
          )}

          <div className="card">
            <h2>Why</h2>
            <Trace entries={result.explain?.trace} />
          </div>
        </>
      )}
    </>
  );
}
