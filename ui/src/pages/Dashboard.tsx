import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Banner, EffectPill, Empty, Loading, Stat, when } from "../components/atoms";

export function Dashboard({ onOpenDecision }: { onOpenDecision: (id: string) => void }) {
  const stats = useAsync(() => api.decisionStats(), []);
  const recent = useAsync(() => api.decisions({ limit: "12" }), []);
  const chain = useAsync(() => api.verifyAudit(), []);
  const ready = useAsync(() => api.ready(), []);

  return (
    <>
      <div className="page-head">
        <h1>Overview</h1>
        <p>
          What the control plane has been asked, what it answered, and whether the
          record of those answers is still intact.
        </p>
      </div>

      {stats.error && <Banner kind="error">{stats.error}</Banner>}

      <div className="grid cols-4">
        <Stat label="Decisions" value={stats.data?.total ?? "—"} />
        <Stat
          label="Denied"
          value={stats.data?.by_effect?.deny ?? 0}
          hint="requests refused outright"
        />
        <Stat
          label="Redactions"
          value={stats.data?.total_redactions ?? 0}
          hint="values rewritten before delivery"
        />
        <Stat
          label="Median latency"
          value={stats.data ? `${stats.data.avg_latency_ms.toFixed(1)} ms` : "—"}
          hint="mean, end to end"
        />
      </div>

      <div className="grid cols-2">
        <div className="card">
          <h2>Posture</h2>
          {ready.data ? (
            <table>
              <tbody>
                <tr>
                  <td className="dim">When no policy matches</td>
                  <td><EffectPill effect={ready.data.default_effect} /></td>
                </tr>
                <tr>
                  <td className="dim">On internal error</td>
                  <td>
                    {ready.data.fail_closed ? (
                      <span className="pill allow">fails closed</span>
                    ) : (
                      <span className="pill deny">fails open</span>
                    )}
                  </td>
                </tr>
                <tr>
                  <td className="dim">Database</td>
                  <td className="mono">{ready.data.database}</td>
                </tr>
              </tbody>
            </table>
          ) : (
            <Loading />
          )}
        </div>

        <div className="card">
          <h2>Audit chain</h2>
          {chain.loading && <Loading />}
          {chain.data && (
            <Banner kind={chain.data.valid ? "ok" : "error"}>
              {chain.data.message}
            </Banner>
          )}
          <p className="small dim">
            Each record’s digest covers its own content and its predecessor’s, so any
            edit, deletion, or reordering shows up as a specific sequence number
            rather than a vague failure.
          </p>
          <button onClick={chain.reload}>Re-verify</button>
        </div>
      </div>

      <div className="card">
        <h2>Which policies are doing the work</h2>
        {stats.data && stats.data.by_policy.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>policy</th><th className="right">decisions</th></tr></thead>
              <tbody>
                {stats.data.by_policy.map((row) => (
                  <tr key={row.policy}>
                    <td className="mono">{row.policy}</td>
                    <td className="right">{row.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty>no decisions recorded yet</Empty>
        )}
      </div>

      <div className="card">
        <h2>Recent decisions</h2>
        {recent.loading && <Loading />}
        {recent.data && recent.data.items.length === 0 && (
          <Empty>
            nothing yet — try the Simulator, or run <span className="mono">make demo</span>
          </Empty>
        )}
        {recent.data && recent.data.items.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>when</th><th>effect</th><th>principal</th><th>action</th>
                  <th>resource</th><th>policy</th><th className="right">ms</th>
                </tr>
              </thead>
              <tbody>
                {recent.data.items.map((decision) => (
                  <tr
                    key={decision.id}
                    className="clickable"
                    onClick={() => onOpenDecision(decision.id)}
                  >
                    <td className="small dim">{when(decision.created_at)}</td>
                    <td><EffectPill effect={decision.effect} /></td>
                    <td className="mono">{decision.principal_id}</td>
                    <td className="mono">{decision.action}</td>
                    <td className="mono">{decision.resource_urn || "—"}</td>
                    <td className="mono small">{decision.determining_policy ?? "—"}</td>
                    <td className="right small">{decision.latency_ms.toFixed(1)}</td>
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
