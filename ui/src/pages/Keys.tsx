import { useState } from "react";
import { api, type ApiKey } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Banner, Empty, Loading, when } from "../components/atoms";

/**
 * Credentials.
 *
 * Issuing is deliberately absent: the plaintext is returned exactly once, and a
 * browser is the wrong place for it to land — it would sit in the tab's memory,
 * in a screenshot, and in whatever the page was later pasted into. `cpctl key
 * issue` puts it in the operator's terminal instead. Listing and revoking are
 * what an operator actually needs at a glance.
 */
export function Keys() {
  const keys = useAsync(() => api.keys(), []);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function revoke(key: ApiKey) {
    if (!confirm(`Revoke ${key.name} (${key.prefix})? This takes effect immediately.`)) {
      return;
    }
    setBusy(key.prefix);
    setError(null);
    try {
      await api.revokeKey(key.prefix);
      keys.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <div className="page-head">
        <h1>Keys</h1>
        <p>
          What each credential may do, and when it was last used. Secrets are
          stored as keyed digests and are never recoverable — this page cannot
          show you one, and neither can the API.
        </p>
        <p className="small dim">
          Issue with <span className="mono">cpctl key issue --name … --scope …</span>.
          The plaintext appears once, in your terminal, which is a better place for
          it than a browser tab.
        </p>
      </div>

      {(keys.error || error) && <Banner kind="error">{keys.error ?? error}</Banner>}
      {keys.loading && <Loading />}
      {keys.data && keys.data.length === 0 && (
        <div className="card"><Empty>no active keys</Empty></div>
      )}

      {keys.data && keys.data.length > 0 && (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>prefix</th><th>name</th><th>scopes</th>
                  <th>bound to</th><th>last used</th><th></th>
                </tr>
              </thead>
              <tbody>
                {keys.data.map((key) => (
                  <tr key={key.prefix}>
                    <td className="mono">{key.prefix}</td>
                    <td>
                      {key.name}
                      {key.description && (
                        <div className="small dim">{key.description}</div>
                      )}
                    </td>
                    <td>
                      {key.scopes.map((scope) => (
                        <span
                          key={scope}
                          className={`tag ${scope === "admin" || scope === "detokenize" ? "critical" : ""}`}
                        >
                          {scope}
                        </span>
                      ))}
                    </td>
                    <td className="small">
                      {key.allowed_principals.length > 0 ? (
                        key.allowed_principals.map((p) => (
                          <span key={p} className="tag">{p}</span>
                        ))
                      ) : (
                        <span className="dim" title="A stolen key could speak for anyone">
                          any principal
                        </span>
                      )}
                    </td>
                    <td className="small dim">
                      {key.last_used_at ? when(key.last_used_at) : "never"}
                    </td>
                    <td className="right">
                      <button disabled={busy === key.prefix} onClick={() => revoke(key)}>
                        {busy === key.prefix ? "…" : "Revoke"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="small dim" style={{ marginTop: 10 }}>
            A key bound to no principal can submit decisions for any of them.
            That suits a shared gateway; a key handed to one agent should name it.
          </p>
        </div>
      )}
    </>
  );
}
