import { useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Banner, Empty, LabelTag, Loading, when } from "../components/atoms";

export function Approvals() {
  const approvals = useAsync(() => api.approvals(), []);
  const [note, setNote] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function resolve(id: string, grant: boolean) {
    setBusy(id);
    setError(null);
    try {
      await api.resolveApproval(id, grant, note[id] ?? "");
      approvals.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <div className="page-head">
        <h1>Approvals</h1>
        <p>
          Decisions a policy parked for a person. The <span className="mono">
          require_approval</span> effect exists so a rule can say “not without a human”
          rather than choosing between blocking legitimate work and waving through
          risky work.
        </p>
      </div>

      {(approvals.error || error) && <Banner kind="error">{approvals.error ?? error}</Banner>}
      {approvals.loading && <Loading />}
      {approvals.data && approvals.data.length === 0 && (
        <div className="card"><Empty>nothing waiting</Empty></div>
      )}

      {approvals.data?.map((approval) => (
        <div className="card" key={approval.id}>
          <div className="spread">
            <div className="row">
              <span className="pill require_approval">{approval.status}</span>
              <strong className="mono">{approval.decision?.action}</strong>
              <span className="mono">{approval.decision?.resource_urn}</span>
            </div>
            <span className="small dim">requested {when(approval.created_at)}</span>
          </div>

          <table style={{ marginTop: 8 }}>
            <tbody>
              <tr><td className="dim">requested by</td>
                <td className="mono">{approval.requested_by}</td></tr>
              <tr><td className="dim">policy</td>
                <td className="mono small">
                  {approval.decision?.determining_policy ?? "—"}</td></tr>
              <tr><td className="dim">data involved</td>
                <td>{(approval.decision?.classifications ?? []).map((key) => (
                  <LabelTag key={key} label={key} />
                ))}</td></tr>
              {approval.justification && (
                <tr><td className="dim">justification</td>
                  <td>{approval.justification}</td></tr>
              )}
              <tr><td className="dim">expires</td>
                <td className="small">{when(approval.expires_at)}</td></tr>
            </tbody>
          </table>

          {approval.status === "pending" && (
            <div style={{ marginTop: 10 }}>
              <div className="field">
                <label>Note — recorded against your name in the audit chain</label>
                <input
                  placeholder="ticket reference, or why this is warranted"
                  value={note[approval.id] ?? ""}
                  onChange={(event) =>
                    setNote((current) => ({ ...current, [approval.id]: event.target.value }))
                  }
                />
              </div>
              <div className="row">
                <button className="primary" disabled={busy === approval.id}
                  onClick={() => resolve(approval.id, true)}>Grant</button>
                <button disabled={busy === approval.id}
                  onClick={() => resolve(approval.id, false)}>Deny</button>
              </div>
            </div>
          )}

          {approval.status !== "pending" && (
            <p className="small dim">
              {approval.status} by {approval.decided_by ?? "—"} · {approval.decision_note || "no note"}
            </p>
          )}
        </div>
      ))}
    </>
  );
}
