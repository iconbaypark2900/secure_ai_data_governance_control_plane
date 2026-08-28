import { Fragment, useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Banner, Empty, Loading, when } from "../components/atoms";

export function Audit() {
  const [event, setEvent] = useState("");
  const chain = useAsync(() => api.verifyAudit(), []);
  const records = useAsync(
    () => api.audit({ limit: "150", ...(event && { event }) }),
    [event],
  );
  const [expanded, setExpanded] = useState<number | null>(null);

  const events = Array.from(
    new Set((records.data?.items ?? []).map((record) => record.event)),
  ).sort();

  return (
    <>
      <div className="page-head">
        <h1>Audit trail</h1>
        <p>
          Every decision and every administrative change, sealed into a hash chain. Each
          record’s digest is an HMAC over its own content and its predecessor’s digest,
          so rewriting history requires the audit key — which does not live in the
          database.
        </p>
      </div>

      <div className="card">
        <div className="spread">
          <h2 style={{ margin: 0 }}>Integrity</h2>
          <button onClick={chain.reload}>Re-verify</button>
        </div>
        {chain.loading && <Loading />}
        {chain.data && (
          <>
            <Banner kind={chain.data.valid ? "ok" : "error"}>{chain.data.message}</Banner>
            {!chain.data.valid && (
              <table>
                <tbody>
                  <tr><td className="dim">altered digests</td>
                    <td className="mono">{chain.data.corrupted.join(", ") || "none"}</td></tr>
                  <tr><td className="dim">broken links</td>
                    <td className="mono">{chain.data.broken_links.join(", ") || "none"}</td></tr>
                  <tr><td className="dim">gaps or repeats</td>
                    <td className="mono">
                      {chain.data.sequence_errors.join(", ") || "none"}</td></tr>
                </tbody>
              </table>
            )}
          </>
        )}
      </div>

      <div className="card">
        <div className="spread">
          <h2 style={{ margin: 0 }}>{records.data?.total ?? 0} records</h2>
          <select value={event} onChange={(e) => setEvent(e.target.value)}>
            <option value="">all events</option>
            {events.map((name) => <option key={name} value={name}>{name}</option>)}
          </select>
        </div>

        {records.error && <Banner kind="error">{records.error}</Banner>}
        {records.loading && <Loading />}
        {records.data && records.data.items.length === 0 && <Empty>nothing recorded</Empty>}
        {records.data && records.data.items.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>seq</th><th>when</th><th>event</th><th>actor</th>
                  <th>subject</th><th>digest</th></tr>
              </thead>
              <tbody>
                {records.data.items.map((record) => (
                  <Fragment key={record.seq}>
                    <tr
                      className="clickable"
                      onClick={() => setExpanded(expanded === record.seq ? null : record.seq)}
                    >
                      <td className="mono">{record.seq}</td>
                      <td className="small dim">{when(record.timestamp)}</td>
                      <td className="mono small">{record.event}</td>
                      <td className="mono small">{record.actor}</td>
                      <td className="mono small">{record.subject}</td>
                      <td className="mono small dim">{record.record_hash.slice(0, 12)}…</td>
                    </tr>
                    {expanded === record.seq && (
                      <tr>
                        <td colSpan={6}>
                          <pre>{JSON.stringify(record.payload, null, 2)}</pre>
                          <p className="small dim mono">
                            prev {record.prev_hash.slice(0, 24)}…<br />
                            this {record.record_hash.slice(0, 24)}…
                          </p>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
