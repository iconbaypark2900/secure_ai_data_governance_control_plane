import { Fragment, useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Banner, Empty, Loading, when } from "../components/atoms";

export function Audit() {
  const [event, setEvent] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const chain = useAsync(() => api.verifyAudit(), []);
  const streams = useAsync(() => api.auditStreams(), []);
  const records = useAsync(
    () => api.audit({ limit: "150", ...(event && { event }) }),
    [event],
  );
  const [expanded, setExpanded] = useState<number | null>(null);

  async function takeCheckpoint() {
    setBusy(true);
    setError(null);
    try {
      await api.checkpoint();
      chain.reload();
      streams.reload();
      records.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

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
          <div className="row">
            <button onClick={takeCheckpoint} disabled={busy}>
              {busy ? "Sealing…" : "Take checkpoint"}
            </button>
            <button onClick={() => { chain.reload(); streams.reload(); }}>Re-verify</button>
          </div>
        </div>
        {chain.loading && <Loading />}
        {error && <Banner kind="error">{error}</Banner>}
        {chain.data && (
          <>
            <Banner kind={chain.data.valid ? "ok" : "error"}>{chain.data.message}</Banner>
            <p className="small dim">
              The log is many chains, one per stream, so appends do not all queue
              behind a single lock. Each verifies on its own — and only the
              checkpoint can notice a whole stream going missing, which is why
              taking them on a schedule matters.
            </p>
            {Object.entries(chain.data.streams).some(([, r]) => !r.valid) && (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr><th>stream</th><th>altered</th><th>broken links</th><th>gaps</th></tr>
                  </thead>
                  <tbody>
                    {Object.entries(chain.data.streams)
                      .filter(([, r]) => !r.valid)
                      .map(([name, r]) => (
                        <tr key={name}>
                          <td className="mono">{name}</td>
                          <td className="mono">{r.corrupted.join(", ") || "—"}</td>
                          <td className="mono">{r.broken_links.join(", ") || "—"}</td>
                          <td className="mono">{r.sequence_errors.join(", ") || "—"}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            )}
            {(chain.data.checkpoint.missing?.length ||
              chain.data.checkpoint.truncated?.length ||
              chain.data.checkpoint.diverged?.length) ? (
              <Banner kind="error">
                {chain.data.checkpoint.message}
              </Banner>
            ) : (
              <p className="small dim">{chain.data.checkpoint.message}</p>
            )}
          </>
        )}
      </div>

      <div className="card">
        <h2>Streams</h2>
        {streams.loading && <Loading />}
        {streams.data && streams.data.count === 0 && <Empty>nothing recorded</Empty>}
        {streams.data && streams.data.count > 0 && (
          <>
            <p className="small dim">
              {streams.data.count} chain(s), {streams.data.total_records} record(s).
            </p>
            <div className="table-wrap">
              <table>
                <thead><tr><th>stream</th><th className="right">records</th><th>head</th></tr></thead>
                <tbody>
                  {streams.data.streams.map((head) => (
                    <tr key={head.stream}>
                      <td className="mono">{head.stream}</td>
                      <td className="right">{head.seq}</td>
                      <td className="mono small dim">{head.head_hash.slice(0, 20)}…</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
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
                <tr><th>stream</th><th>seq</th><th>when</th><th>event</th>
                  <th>actor</th><th>subject</th><th>digest</th></tr>
              </thead>
              <tbody>
                {records.data.items.map((record) => (
                  <Fragment key={record.seq}>
                    <tr
                      className="clickable"
                      onClick={() => setExpanded(expanded === record.seq ? null : record.seq)}
                    >
                      <td className="mono small dim">{record.stream}</td>
                      <td className="mono">{record.seq}</td>
                      <td className="small dim">{when(record.timestamp)}</td>
                      <td className="mono small">{record.event}</td>
                      <td className="mono small">{record.actor}</td>
                      <td className="mono small">{record.subject}</td>
                      <td className="mono small dim">{record.record_hash.slice(0, 12)}…</td>
                    </tr>
                    {expanded === record.seq && (
                      <tr>
                        <td colSpan={7}>
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
