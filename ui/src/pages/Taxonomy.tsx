import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Banner, Loading } from "../components/atoms";

export function TaxonomyPage() {
  const taxonomy = useAsync(() => api.taxonomy(), []);
  const schema = useAsync(() => api.policySchema(), []);

  return (
    <>
      <div className="page-head">
        <h1>Taxonomy</h1>
        <p>
          The label vocabulary every other part of the system shares: the catalog tags
          assets with these, policies match on them, and redaction obligations name them.
          Labels are hierarchical — a policy naming <span className="mono">pii</span>{" "}
          covers every <span className="mono">pii.*</span> beneath it.
        </p>
      </div>

      {schema.data && (
        <div className="card">
          <h2>The policy language</h2>
          <p className="small dim">
            Served from the running engine rather than a document, so it cannot
            drift from what is actually accepted.
          </p>
          <table>
            <tbody>
              <tr><td className="dim">selectors</td>
                <td>{schema.data.selectors.map((x) => <span key={x} className="tag">{x}</span>)}</td></tr>
              <tr><td className="dim">operators</td>
                <td>{schema.data.operators.map((x) => <span key={x} className="tag">{x}</span>)}</td></tr>
              <tr><td className="dim">effects</td>
                <td>{schema.data.effects.map((x) => <span key={x} className="tag">{x}</span>)}</td></tr>
              <tr><td className="dim">combinators</td>
                <td>{schema.data.combinators.map((x) => <span key={x} className="tag">{x}</span>)}</td></tr>
              <tr><td className="dim">obligations</td>
                <td>{schema.data.obligation_types.map((x) => <span key={x} className="tag">{x}</span>)}</td></tr>
              <tr><td className="dim">redaction</td>
                <td>{schema.data.redaction_strategies.map((x) => <span key={x} className="tag">{x}</span>)}</td></tr>
            </tbody>
          </table>
        </div>
      )}

      {taxonomy.error && <Banner kind="error">{taxonomy.error}</Banner>}
      {taxonomy.loading && <Loading />}

      {taxonomy.data && (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>key</th><th>name</th><th>severity</th>
                  <th>detected</th><th>regulations</th><th>description</th>
                </tr>
              </thead>
              <tbody>
                {taxonomy.data.labels.map((label) => (
                  <tr key={label.key}>
                    <td className="mono">{label.key}</td>
                    <td className="small">{label.name}</td>
                    <td>
                      <span className={`tag ${label.severity}`}>{label.severity}</span>
                    </td>
                    <td className="small">
                      {label.automatically_detected ? (
                        <span className="dim" title={(label.detectors ?? []).join(", ")}>
                          {(label.detectors ?? []).length} detector
                          {(label.detectors ?? []).length === 1 ? "" : "s"}
                        </span>
                      ) : (
                        <span className="dim" title="Needs a human or a model">manual</span>
                      )}
                    </td>
                    <td className="small dim">{label.regulations.join(", ") || "—"}</td>
                    <td className="small dim">{label.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="small dim" style={{ marginTop: 10 }}>
            “manual” means no regex can honestly identify it — <span className="mono">
            pii.name</span> needs a model, and pretending otherwise would produce a
            detector that is confidently wrong.
          </p>
        </div>
      )}
    </>
  );
}
