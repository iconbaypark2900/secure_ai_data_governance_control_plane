import { useState } from "react";
import { api, type DetokenizeResult } from "../lib/api";
import { Banner, Empty } from "../components/atoms";

/**
 * Re-identification.
 *
 * The most sensitive thing the console can do, so it is built to look like it:
 * a justification is required, every call is recorded against the operator's
 * name, and the verify form is presented first because it answers the usual
 * question without disclosing anything.
 */
export function Tokens() {
  return (
    <>
      <div className="page-head">
        <h1>Tokens</h1>
        <p>
          Tokenisation has no vault — the token <em>is</em> the ciphertext, so
          there is no table of sensitive values to steal. Reversing one needs the
          key, and every attempt is recorded against your name whether or not it
          succeeds.
        </p>
      </div>
      <VerifyForm />
      <ReverseForm />
    </>
  );
}

function VerifyForm() {
  const [token, setToken] = useState("");
  const [label, setLabel] = useState("pii.email");
  const [value, setValue] = useState("");
  const [justification, setJustification] = useState("");
  const [result, setResult] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const response = await api.verifyToken({ token, label, value, justification });
      setResult(response.matches);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h2>Confirm a match</h2>
      <p className="small dim">
        “Is this token this value?” — answered without disclosing anything, which
        is the real question most of the time. Reach for this before reversing.
      </p>
      {error && <Banner kind="error">{error}</Banner>}
      <div className="grid cols-2">
        <div className="field">
          <label>Token</label>
          <input className="mono" placeholder="tok_…" value={token}
            onChange={(e) => setToken(e.target.value)} />
        </div>
        <div className="field">
          <label>Label it was minted under</label>
          <input className="mono" value={label} onChange={(e) => setLabel(e.target.value)} />
        </div>
      </div>
      <div className="field">
        <label>The value you believe it stands for</label>
        <input value={value} onChange={(e) => setValue(e.target.value)} />
      </div>
      <div className="field">
        <label>Justification — recorded against your name</label>
        <input placeholder="incident INC-4821" value={justification}
          onChange={(e) => setJustification(e.target.value)} />
      </div>
      <button className="primary" onClick={submit}
        disabled={busy || !token || !value || justification.trim().length < 3}>
        {busy ? "Checking…" : "Check"}
      </button>
      {result !== null && (
        <Banner kind={result ? "ok" : "error"}>
          {result ? "the token stands for that value" : "it does not"}
        </Banner>
      )}
    </div>
  );
}

function ReverseForm() {
  const [raw, setRaw] = useState("");
  const [justification, setJustification] = useState("");
  const [results, setResults] = useState<DetokenizeResult[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const tokens = raw.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean);

  async function submit() {
    setBusy(true);
    setError(null);
    setResults(null);
    try {
      setResults((await api.detokenize(tokens, justification)).results);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h2>Reverse</h2>
      <p className="small dim">
        Needs the <span className="mono">detokenize</span> scope, which can be
        granted on its own — an investigator does not also need the catalog.
        Batches are capped at 50: a row of tokens is an investigation, a table of
        them is something else.
      </p>
      {error && <Banner kind="error">{error}</Banner>}
      <div className="field">
        <label>Tokens — one per line</label>
        <textarea rows={4} className="mono" value={raw}
          onChange={(e) => setRaw(e.target.value)} placeholder="tok_…" />
      </div>
      <div className="field">
        <label>Justification — required, and recorded whether or not this succeeds</label>
        <input placeholder="incident INC-4821" value={justification}
          onChange={(e) => setJustification(e.target.value)} />
      </div>
      <div className="row">
        <button className="primary" onClick={submit}
          disabled={busy || tokens.length === 0 || justification.trim().length < 3}>
          {busy ? "Reversing…" : `Reverse ${tokens.length || ""}`}
        </button>
        {tokens.length > 50 && (
          <span className="pill deny">{tokens.length} exceeds the batch limit</span>
        )}
      </div>

      {results && (
        results.length === 0 ? <Empty>nothing to show</Empty> : (
          <div className="table-wrap" style={{ marginTop: 12 }}>
            <table>
              <thead><tr><th>token</th><th>value</th></tr></thead>
              <tbody>
                {results.map((result) => (
                  <tr key={result.token}>
                    <td className="mono small dim">{result.token.slice(0, 28)}…</td>
                    <td>
                      {result.recovered
                        ? <span className="mono">{result.value}</span>
                        : <span className="dim small">not readable with this key</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
      {results && (
        <p className="small dim">
          A token that cannot be read comes back the same way whether it was
          malformed, minted under a key this deployment no longer holds, or
          tampered with — so this cannot be used to tell those apart.
        </p>
      )}
    </div>
  );
}
