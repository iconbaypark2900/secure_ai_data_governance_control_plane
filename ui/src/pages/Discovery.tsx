import { useState } from "react";
import { api, type DiscoveryReport, type Source } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Banner, Empty, LabelTag, Loading } from "../components/atoms";

export function Discovery() {
  const sources = useAsync(() => api.sources(), []);
  const [report, setReport] = useState<DiscoveryReport | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run(source: Source, options: { dry_run: boolean; scan: boolean }) {
    setBusy(source.name);
    setError(null);
    setReport(null);
    try {
      setReport(await api.discover(source.name, options));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <div className="page-head">
        <h1>Discovery</h1>
        <p>
          A control plane only governs what it knows about, and a catalog kept by
          hand is a catalog with holes in it. Point it at the systems that hold
          data and let it enumerate them.
        </p>
        <p className="small dim">
          Credentials are configured server-side and referred to by name, so a
          connection string never travels in a request. Start with a dry run:
          it reads nothing and writes nothing.
        </p>
      </div>

      {(sources.error || error) && <Banner kind="error">{sources.error ?? error}</Banner>}
      {sources.loading && <Loading />}

      {sources.data && sources.data.length === 0 && (
        <div className="card">
          <Empty>
            no sources configured — see <span className="mono">seed/sources.example.yaml</span>
          </Empty>
        </div>
      )}

      {sources.data?.map((source) => (
        <div className="card" key={source.name}>
          <div className="spread">
            <div className="row">
              <strong className="mono">{source.name}</strong>
              <span className="pill neutral">{source.adapter}</span>
              {source.target === "[not configured]" ? (
                <span className="pill deny">not configured</span>
              ) : (
                <span className="mono small dim">{source.target}</span>
              )}
              {!source.enabled && <span className="pill neutral">disabled</span>}
            </div>
            <div className="row">
              <button
                disabled={busy !== null || !source.enabled}
                onClick={() => run(source, { dry_run: true, scan: false })}
              >
                {busy === source.name ? "Running…" : "Dry run"}
              </button>
              <button
                className="primary"
                disabled={busy !== null || !source.enabled}
                onClick={() => run(source, { dry_run: false, scan: source.scan })}
              >
                Discover{source.scan ? " and scan" : ""}
              </button>
            </div>
          </div>

          {source.description && <p className="dim">{source.description}</p>}
          <div className="row small dim">
            {source.owner && <span>owner {source.owner}</span>}
            <span>max {source.max_assets}</span>
            {source.scan && <span>samples {source.sample_limit} record(s) per asset</span>}
          </div>
          {source.exclude.length > 0 && (
            <p className="small dim">
              never sampled:{" "}
              {source.exclude.map((pattern) => (
                <span key={pattern} className="tag">{pattern}</span>
              ))}
            </p>
          )}
        </div>
      ))}

      {report && <Report report={report} />}
    </>
  );
}

function Report({ report }: { report: DiscoveryReport }) {
  return (
    <div className="card">
      <div className="spread">
        <h2 style={{ margin: 0 }}>
          {report.source} · {report.discovered} asset(s)
        </h2>
        <span className="small dim">{report.duration_ms.toFixed(0)} ms</span>
      </div>

      {report.dry_run && (
        <Banner kind="">dry run — nothing was written, and nothing was read</Banner>
      )}
      {report.errors.length > 0 && <Banner kind="error">{report.errors.join("; ")}</Banner>}
      {report.truncated && (
        <Banner kind="error">
          capped by max_assets — coverage is incomplete
        </Banner>
      )}

      <div className="row small dim">
        <span>{report.created} new</span>
        <span>{report.updated} existing</span>
        {report.failed > 0 && <span className="pill deny">{report.failed} failed</span>}
        {report.regulations.length > 0 && (
          <span>implicates {report.regulations.join(", ")}</span>
        )}
      </div>

      {report.assets.length === 0 ? (
        <Empty>nothing found</Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>urn</th><th>kind</th><th></th><th>labels</th><th>sampled</th>
              </tr>
            </thead>
            <tbody>
              {report.assets.map((asset) => (
                <tr key={asset.urn}>
                  <td className="mono">{asset.urn}</td>
                  <td className="small">{asset.kind}</td>
                  <td>
                    {asset.error ? (
                      <span className="pill deny" title={asset.error}>failed</span>
                    ) : asset.created ? (
                      <span className="pill allow">new</span>
                    ) : (
                      <span className="pill neutral">existing</span>
                    )}
                  </td>
                  <td>
                    {asset.labels_imported.map((label) => (
                      <span key={`i-${label}`} className="tag" title="asserted by the source">
                        {label}
                      </span>
                    ))}
                    {asset.labels_scanned.map((label) => (
                      <LabelTag key={`s-${label}`} label={label} />
                    ))}
                  </td>
                  <td className="small dim">
                    {asset.sampled
                      ? `${asset.records_sampled}${asset.partial_sample ? " (partial)" : ""}`
                      : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {report.assets.some((a) => a.error) && (
        <p className="small dim">
          One asset failing does not fail the run — the rest are still catalogued,
          because a table the credentials cannot read should not hide the four
          hundred that they can.
        </p>
      )}
    </div>
  );
}
