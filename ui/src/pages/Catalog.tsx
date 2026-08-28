import { useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Banner, Empty, LabelTag, Loading, when } from "../components/atoms";

export function Catalog() {
  const [search, setSearch] = useState("");
  const [label, setLabel] = useState("");
  const [probe, setProbe] = useState("");

  const assets = useAsync(
    () => api.assets({ ...(search && { search }), ...(label && { label }) }),
    [search, label],
  );
  const principals = useAsync(() => api.principals(), []);
  const resolved = useAsync(
    () => (probe ? api.resolveAsset(probe) : Promise.resolve(null)),
    [probe],
  );

  return (
    <>
      <div className="page-head">
        <h1>Catalog</h1>
        <p>
          What each store holds, and who is allowed to be interested in it. Entries
          containing <span className="mono">*</span> are patterns: they classify every
          asset beneath them, so a table nobody remembered to register is still governed.
        </p>
      </div>

      <div className="card">
        <h2>Resolve a URN</h2>
        <p className="small dim">
          Exactly what the policy engine would see for an identifier — including labels
          inherited from a pattern, which is the answer to “why is this table treated as PHI?”
        </p>
        <div className="row">
          <input
            placeholder="pg://clinical.a_table_nobody_registered"
            defaultValue=""
            onKeyDown={(event) => {
              if (event.key === "Enter") setProbe(event.currentTarget.value.trim());
            }}
          />
        </div>
        {resolved.data && (
          <div style={{ marginTop: 10 }}>
            <div className="row">
              <span className="mono">{resolved.data.urn}</span>
              {resolved.data.registered
                ? <span className="pill allow">known</span>
                : <span className="pill deny">unregistered</span>}
            </div>
            <div style={{ marginTop: 6 }}>
              {resolved.data.classifications.length > 0
                ? resolved.data.classifications.map((key) => <LabelTag key={key} label={key} />)
                : <span className="dim small">no labels</span>}
            </div>
            {resolved.data.matched_patterns.length > 0 && (
              <p className="small dim">
                inherited from {resolved.data.matched_patterns.join(", ")}
              </p>
            )}
            {resolved.data.regulations.length > 0 && (
              <p className="small dim">implicates {resolved.data.regulations.join(", ")}</p>
            )}
          </div>
        )}
        {resolved.error && <Banner kind="error">{resolved.error}</Banner>}
      </div>

      <div className="card">
        <div className="spread">
          <h2 style={{ margin: 0 }}>Data assets</h2>
          <div className="row">
            <input
              style={{ width: 200 }}
              placeholder="search"
              onChange={(event) => setSearch(event.target.value)}
            />
            <select value={label} onChange={(event) => setLabel(event.target.value)}>
              <option value="">all labels</option>
              <option value="pii">pii</option>
              <option value="phi">phi</option>
              <option value="pci">pci</option>
              <option value="secret">secret</option>
              <option value="confidential">confidential</option>
              <option value="public">public</option>
            </select>
          </div>
        </div>

        {assets.error && <Banner kind="error">{assets.error}</Banner>}
        {assets.loading && <Loading />}
        {assets.data && assets.data.length === 0 && <Empty>no assets registered</Empty>}
        {assets.data && assets.data.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>urn</th><th>kind</th><th>owner</th>
                  <th>labels</th><th>regulations</th><th>scanned</th>
                </tr>
              </thead>
              <tbody>
                {assets.data.map((asset) => (
                  <tr key={asset.urn}>
                    <td>
                      <div className="mono">{asset.urn}</div>
                      {asset.name !== asset.urn && (
                        <div className="small dim">{asset.name}</div>
                      )}
                    </td>
                    <td className="small">{asset.kind}</td>
                    <td className="small dim">{asset.owner || "—"}</td>
                    <td>
                      {asset.classifications.map((classification) => (
                        <span
                          key={`${classification.label}-${classification.source}`}
                          className="tag"
                          title={`${classification.source}, confidence ${classification.confidence}`}
                        >
                          {classification.label}
                        </span>
                      ))}
                    </td>
                    <td className="small dim">{asset.regulations.join(", ") || "—"}</td>
                    <td className="small dim">{when(asset.last_scanned_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <h2>Principals</h2>
        <p className="small dim">
          Attributes here are authoritative — they override anything a caller asserts
          about itself, so an agent cannot promote its own trust tier.
        </p>
        {principals.loading && <Loading />}
        {principals.data && (
          <div className="table-wrap">
            <table>
              <thead><tr><th>id</th><th>type</th><th>name</th><th>attributes</th></tr></thead>
              <tbody>
                {principals.data.map((principal) => (
                  <tr key={principal.external_id}>
                    <td className="mono">{principal.external_id}</td>
                    <td className="small">{principal.type}</td>
                    <td className="small">{principal.display_name || "—"}</td>
                    <td>
                      {Object.entries(principal.attributes).map(([key, value]) => (
                        <span key={key} className="tag">{key}={String(value)}</span>
                      ))}
                    </td>
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
