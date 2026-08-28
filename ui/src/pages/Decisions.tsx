import { useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Banner, EffectPill, Empty, LabelTag, Loading, when } from "../components/atoms";
import { Trace } from "../components/Trace";

export function Decisions({
  openId, onOpen,
}: {
  openId: string | null; onOpen: (id: string | null) => void;
}) {
  const [effect, setEffect] = useState("");
  const decisions = useAsync(
    () => api.decisions({ limit: "100", ...(effect && { effect }) }),
    [effect],
  );

  if (openId) return <DecisionDetail id={openId} onBack={() => onOpen(null)} />;

  return (
    <>
      <div className="page-head">
        <h1>Decisions</h1>
        <p>
          Every question the control plane has been asked. No payload content is stored —
          only the labels found in it and a keyed digest, so an investigator can match a
          decision to a document they already hold without the log becoming a copy of it.
        </p>
      </div>

      <div className="card">
        <div className="spread">
          <h2 style={{ margin: 0 }}>{decisions.data?.total ?? 0} recorded</h2>
          <select value={effect} onChange={(event) => setEffect(event.target.value)}>
            <option value="">all effects</option>
            <option value="allow">allow</option>
            <option value="deny">deny</option>
            <option value="require_approval">require approval</option>
          </select>
        </div>

        {decisions.error && <Banner kind="error">{decisions.error}</Banner>}
        {decisions.loading && <Loading />}
        {decisions.data && decisions.data.items.length === 0 && <Empty>nothing recorded</Empty>}
        {decisions.data && decisions.data.items.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>when</th><th>effect</th><th>principal</th><th>action</th>
                  <th>resource</th><th>labels</th><th>policy</th>
                  <th className="right">redactions</th>
                </tr>
              </thead>
              <tbody>
                {decisions.data.items.map((decision) => (
                  <tr key={decision.id} className="clickable" onClick={() => onOpen(decision.id)}>
                    <td className="small dim">{when(decision.created_at)}</td>
                    <td><EffectPill effect={decision.effect} /></td>
                    <td className="mono">{decision.principal_id}</td>
                    <td className="mono">{decision.action}</td>
                    <td className="mono small">{decision.resource_urn || "—"}</td>
                    <td>
                      {decision.classifications.slice(0, 3).map((key) => (
                        <LabelTag key={key} label={key} />
                      ))}
                      {decision.classifications.length > 3 && (
                        <span className="small dim">
                          +{decision.classifications.length - 3}
                        </span>
                      )}
                    </td>
                    <td className="mono small">{decision.determining_policy ?? "—"}</td>
                    <td className="right">{decision.redaction_count || ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}

function DecisionDetail({ id, onBack }: { id: string; onBack: () => void }) {
  const decision = useAsync(() => api.decision(id), [id]);

  return (
    <>
      <div className="page-head">
        <button onClick={onBack}>← Back</button>
        <h1 style={{ marginTop: 10 }}>Decision</h1>
        <p className="mono small">{id}</p>
      </div>

      {decision.error && <Banner kind="error">{decision.error}</Banner>}
      {decision.loading && <Loading />}

      {decision.data && (
        <>
          <div className="card">
            <div className="row">
              <EffectPill effect={decision.data.effect} />
              <strong>{decision.data.determining_policy ?? "no policy matched"}</strong>
              <span className="small dim">{decision.data.latency_ms.toFixed(1)} ms</span>
            </div>
            <p className="dim">{decision.data.reason}</p>

            <table>
              <tbody>
                <tr><td className="dim">principal</td>
                  <td className="mono">{decision.data.principal_id}
                    <span className="small dim"> ({decision.data.principal_type})</span></td></tr>
                <tr><td className="dim">action</td>
                  <td className="mono">{decision.data.action}</td></tr>
                <tr><td className="dim">resource</td>
                  <td className="mono">{decision.data.resource_urn || "—"}</td></tr>
                <tr><td className="dim">labels</td>
                  <td>{decision.data.classifications.map((key) => (
                    <LabelTag key={key} label={key} />
                  ))}</td></tr>
                <tr><td className="dim">matched</td>
                  <td className="mono small">
                    {decision.data.matched_policies.join(", ") || "—"}</td></tr>
                <tr><td className="dim">findings</td>
                  <td>{decision.data.finding_count} detected,{" "}
                    {decision.data.redaction_count} redacted</td></tr>
                <tr><td className="dim">when</td>
                  <td className="small">{when(decision.data.created_at)}</td></tr>
                {decision.data.correlation_id && (
                  <tr><td className="dim">correlation</td>
                    <td className="mono small">{decision.data.correlation_id}</td></tr>
                )}
              </tbody>
            </table>
          </div>

          {decision.data.route && (
            <div className="card">
              <h2>Where it was sent</h2>
              <div className="row">
                <span className="mono">{decision.data.route.target ?? "nowhere"}</span>
                {decision.data.route.redirected
                  ? <span className="pill require_approval">redirected</span>
                  : <span className="pill neutral">as requested</span>}
              </div>
              <p className="dim">{decision.data.route.reason}</p>
              {Object.keys(decision.data.route.rejected).length > 0 && (
                <>
                  <p className="small dim">
                    Why the others lost — “why did my request go there?” is asked
                    far more often than it is answerable.
                  </p>
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>model</th><th>reason</th></tr></thead>
                      <tbody>
                        {Object.entries(decision.data.route.rejected).map(([urn, why]) => (
                          <tr key={urn}>
                            <td className="mono">{urn}</td>
                            <td className="small dim">{why}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          )}

          {decision.data.obligations.length > 0 && (
            <div className="card">
              <h2>Obligations</h2>
              <pre>{JSON.stringify(decision.data.obligations, null, 2)}</pre>
            </div>
          )}

          <div className="card">
            <h2>Context</h2>
            <pre>{JSON.stringify(decision.data.context, null, 2)}</pre>
          </div>

          <div className="card">
            <h2>Why</h2>
            <Trace entries={decision.data.trace?.trace} />
          </div>
        </>
      )}
    </>
  );
}
