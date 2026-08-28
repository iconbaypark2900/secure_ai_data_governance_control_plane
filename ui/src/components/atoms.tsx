/** Small shared pieces. */

import type { ReactNode } from "react";
import type { Effect, Finding } from "../lib/api";

export function EffectPill({ effect }: { effect: Effect | string }) {
  const text = effect === "require_approval" ? "approval" : effect;
  return <span className={`pill ${effect}`}>{text}</span>;
}

/**
 * What actually happened, as distinct from what was permitted.
 *
 * Unreported is shown rather than hidden: an enforcement point that quietly
 * stops reporting is one that quietly stopped being observed, and treating
 * silence as success is the assumption this whole field exists to remove.
 */
export function OutcomePill({ outcome }: { outcome: string | null }) {
  if (outcome === null) {
    return (
      <span className="pill neutral" title="No enforcement point has accounted for this">
        unreported
      </span>
    );
  }
  const style =
    outcome === "enforced" ? "allow" : outcome === "partial" ? "require_approval" : "deny";
  return <span className={`pill ${style}`}>{outcome}</span>;
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="card stat">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {hint && <div className="small dim">{hint}</div>}
    </div>
  );
}

/** A label key, coloured by how bad disclosure would be. */
export function LabelTag({ label, severity }: { label: string; severity?: string }) {
  return <span className={`tag ${severity ?? ""}`}>{label}</span>;
}

export function Banner({ kind, children }: { kind: "error" | "ok" | ""; children: ReactNode }) {
  return <div className={`banner ${kind}`}>{children}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function Loading() {
  return <div className="empty">loading…</div>;
}

export function when(value: string | null | undefined): string {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

/**
 * Findings, rendered from masked previews only.
 *
 * The API never returns the matched value, so this table cannot leak one even
 * if someone screenshots it into a ticket.
 */
export function FindingsTable({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return <Empty>nothing detected</Empty>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>label</th><th>severity</th><th>confidence</th><th>where</th><th>preview</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding, index) => (
            <tr key={`${finding.label}-${finding.start}-${index}`}>
              <td><LabelTag label={finding.label} severity={finding.severity} /></td>
              <td className="small">{finding.severity}</td>
              <td className="small">{finding.confidence.toFixed(2)}</td>
              <td className="mono">{finding.path || `${finding.start}:${finding.end}`}</td>
              <td className="mono dim">{finding.preview}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
