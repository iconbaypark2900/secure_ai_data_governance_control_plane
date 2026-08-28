/**
 * The evaluation trace.
 *
 * This is the component that turns the control plane from an oracle into
 * something auditable: every policy that was considered, whether it applied,
 * and for the ones that did not, the exact condition that ruled them out.
 */

import type { TraceEntry } from "../lib/api";
import { EffectPill, Empty } from "./atoms";

export function Trace({ entries }: { entries: TraceEntry[] | undefined }) {
  if (!entries || entries.length === 0) {
    return <Empty>no trace recorded — re-run the decision with “explain” enabled</Empty>;
  }
  const matched = entries.filter((entry) => entry.matched);
  return (
    <>
      <p className="small dim">
        {entries.length} polic{entries.length === 1 ? "y" : "ies"} evaluated,{" "}
        {matched.length} matched.
      </p>
      {entries.map((entry) => (
        <div key={entry.key} className={`trace-row ${entry.matched ? "matched" : ""}`}>
          <div className="row">
            <EffectPill effect={entry.effect} />
            <strong className="small">{entry.name}</strong>
            <span className="mono dim">{entry.key}</span>
            <span className="small dim">priority {entry.priority}</span>
            {entry.matched ? (
              <span className="pill allow">matched</span>
            ) : (
              <span className="pill neutral">no match</span>
            )}
          </div>
          <div className="small dim">{entry.reason}</div>
          {entry.conditions.length > 0 && (
            <ul className="small dim" style={{ margin: "4px 0 0", paddingLeft: 18 }}>
              {entry.conditions.map((condition, index) => (
                <li key={index} style={{ opacity: condition.passed ? 1 : 0.72 }}>
                  {condition.passed ? "✓" : "✗"} {condition.description}
                </li>
              ))}
            </ul>
          )}
        </div>
      ))}
    </>
  );
}
