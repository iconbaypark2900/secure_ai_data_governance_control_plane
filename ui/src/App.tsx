import { useEffect, useState } from "react";
import { api, getApiKey, setApiKey } from "./lib/api";
import { Dashboard } from "./pages/Dashboard";
import { Policies } from "./pages/Policies";
import { Catalog } from "./pages/Catalog";
import { Decisions } from "./pages/Decisions";
import { Simulator } from "./pages/Simulator";
import { Audit } from "./pages/Audit";
import { Approvals } from "./pages/Approvals";
import { TaxonomyPage } from "./pages/Taxonomy";
import { Banner } from "./components/atoms";

type View =
  | "dashboard" | "simulator" | "policies" | "catalog"
  | "decisions" | "approvals" | "audit" | "taxonomy";

const NAV: { id: View; label: string }[] = [
  { id: "dashboard", label: "Overview" },
  { id: "simulator", label: "Simulator" },
  { id: "policies", label: "Policies" },
  { id: "catalog", label: "Catalog" },
  { id: "decisions", label: "Decisions" },
  { id: "approvals", label: "Approvals" },
  { id: "audit", label: "Audit trail" },
  { id: "taxonomy", label: "Taxonomy" },
];

export function App() {
  const [view, setView] = useState<View>("dashboard");
  const [openDecision, setOpenDecision] = useState<string | null>(null);
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [environment, setEnvironment] = useState("");

  // Probe an authenticated endpoint on load. `/health` is deliberately
  // unauthenticated, so it cannot tell us whether the key we hold is usable.
  useEffect(() => {
    let live = true;
    api
      .health()
      .then((health) => live && setEnvironment(health.environment))
      .catch(() => undefined);
    api
      .policies()
      .then(() => live && setAuthed(true))
      .catch(() => live && setAuthed(false));
    return () => {
      live = false;
    };
  }, []);

  function openDecisionFrom(id: string) {
    setOpenDecision(id);
    setView("decisions");
  }

  if (authed === false) return <KeyGate onDone={() => setAuthed(true)} />;

  return (
    <div className="shell">
      <nav className="sidebar">
        <div className="brand">
          Data Governance
          <small>Control Plane{environment && ` · ${environment}`}</small>
        </div>
        {NAV.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${view === item.id ? "active" : ""}`}
            onClick={() => {
              setView(item.id);
              if (item.id !== "decisions") setOpenDecision(null);
            }}
          >
            {item.label}
          </button>
        ))}
        <div style={{ flex: 1 }} />
        <a className="small dim" href="/docs" target="_blank" rel="noreferrer">
          API reference ↗
        </a>
      </nav>

      <main className="main">
        {view === "dashboard" && <Dashboard onOpenDecision={openDecisionFrom} />}
        {view === "simulator" && <Simulator />}
        {view === "policies" && <Policies />}
        {view === "catalog" && <Catalog />}
        {view === "decisions" && (
          <Decisions openId={openDecision} onOpen={setOpenDecision} />
        )}
        {view === "approvals" && <Approvals />}
        {view === "audit" && <Audit />}
        {view === "taxonomy" && <TaxonomyPage />}
      </main>
    </div>
  );
}

function KeyGate({ onDone }: { onDone: () => void }) {
  const [value, setValue] = useState(getApiKey());
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    setApiKey(value);
    try {
      await api.policies();
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setApiKey("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="gate">
      <div className="card">
        <h2>API key</h2>
        <p className="small dim">
          Held for this browser tab only — it is not written to durable storage, so it
          does not outlive the session it was typed into.
        </p>
        {error && <Banner kind="error">{error}</Banner>}
        <div className="field">
          <input
            type="password"
            placeholder="cpk_…"
            value={value}
            onChange={(event) => setValue(event.target.value)}
            onKeyDown={(event) => event.key === "Enter" && submit()}
          />
        </div>
        <button className="primary" onClick={submit} disabled={busy || !value.trim()}>
          {busy ? "Checking…" : "Continue"}
        </button>
        <p className="small dim" style={{ marginTop: 12 }}>
          Issue one with <span className="mono">cpctl key issue --name console --scope admin</span>
        </p>
      </div>
    </div>
  );
}
