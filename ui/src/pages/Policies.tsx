import { useState } from "react";
import { api, type Policy } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Banner, EffectPill, Loading, when } from "../components/atoms";

export function Policies() {
  const policies = useAsync(() => api.policies(), []);
  const [selected, setSelected] = useState<Policy | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function toggle(policy: Policy) {
    setBusy(true);
    setError(null);
    try {
      await api.setPolicyEnabled(policy.key, !policy.enabled);
      policies.reload();
      setSelected(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="page-head">
        <h1>Policies</h1>
        <p>
          Read top to bottom as a statement of posture: the highest priorities are the
          things that must never happen, the lowest are the ordinary permissions that
          make the system usable. Nothing is permitted implicitly.
        </p>
      </div>

      {(policies.error || error) && <Banner kind="error">{policies.error ?? error}</Banner>}
      {policies.loading && <Loading />}

      {policies.data && (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>priority</th><th>effect</th><th>key</th><th>name</th>
                  <th>tags</th><th>v</th><th>enabled</th>
                </tr>
              </thead>
              <tbody>
                {policies.data.map((policy) => (
                  <tr
                    key={policy.key}
                    className="clickable"
                    onClick={() => setSelected(policy)}
                    style={{ opacity: policy.enabled ? 1 : 0.55 }}
                  >
                    <td className="mono">{policy.priority}</td>
                    <td><EffectPill effect={policy.effect} /></td>
                    <td className="mono">{policy.key}</td>
                    <td>{policy.name}</td>
                    <td>{policy.tags.map((tag) => <span key={tag} className="tag">{tag}</span>)}</td>
                    <td className="small dim">{policy.version}</td>
                    <td>
                      {policy.enabled
                        ? <span className="pill allow">on</span>
                        : <span className="pill neutral">off</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {selected && <PolicyDetail policy={selected} busy={busy} onToggle={toggle}
        onClose={() => setSelected(null)} />}
    </>
  );
}

function PolicyDetail({
  policy, busy, onToggle, onClose,
}: {
  policy: Policy; busy: boolean;
  onToggle: (policy: Policy) => void; onClose: () => void;
}) {
  const versions = useAsync(() => api.policyVersions(policy.key), [policy.key]);

  return (
    <div className="card">
      <div className="spread">
        <h2 style={{ margin: 0 }}>{policy.name}</h2>
        <div className="row">
          <button onClick={() => onToggle(policy)} disabled={busy}>
            {policy.enabled ? "Disable" : "Enable"}
          </button>
          <button onClick={onClose}>Close</button>
        </div>
      </div>

      {policy.description && <p className="dim">{policy.description}</p>}

      <div className="row small dim" style={{ marginBottom: 10 }}>
        <span>version {policy.version}</span>
        <span>·</span>
        <span>updated {when(policy.updated_at)}</span>
        {policy.updated_by && <><span>·</span><span>by {policy.updated_by}</span></>}
      </div>

      <h2>Document</h2>
      <pre>{JSON.stringify(policy.document, null, 2)}</pre>

      <h2 style={{ marginTop: 16 }}>History</h2>
      <p className="small dim">
        Every change is snapshotted, so a decision made months ago can be re-evaluated
        against the policy text that actually governed it.
      </p>
      {versions.loading && <Loading />}
      {versions.data && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>v</th><th>when</th><th>by</th><th>note</th></tr></thead>
            <tbody>
              {versions.data.map((version) => (
                <tr key={version.version}>
                  <td className="mono">{version.version}</td>
                  <td className="small dim">{when(version.created_at)}</td>
                  <td className="small">{version.changed_by || "—"}</td>
                  <td className="small">{version.change_note || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
