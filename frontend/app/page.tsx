"use client";
import { useState, useEffect, useCallback } from "react";
import {
  Shield,
  LayoutDashboard,
  Network,
  Server,
  Search,
  Route,
  Wrench,
  Sparkles,
  ArrowUpRight,
  Upload,
  ChevronRight,
  Activity,
  Download,
  Plus,
} from "lucide-react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

type Asset = {
  id: string;
  name: string;
  type: string;
  criticality: number;
  internet_exposed: boolean;
  owner: string;
};
type Finding = {
  id: string;
  asset_id: string;
  asset_name: string;
  title: string;
  cvss: number;
  risk: number;
  category: string;
  confidence: number;
  explanation: string;
  missing: string[];
  evidence: {
    id: string;
    source: string;
    collected_at: string;
    reliability: number;
    supports: boolean;
  }[];
  contributions: Record<string, number>;
  status: string;
};
type PathItem = {
  id: string;
  nodes: string[];
  risk: number;
  confidence: number;
  target: string;
  inferred: boolean;
  finding_ids: string[];
};
type Analysis = {
  risk: number;
  objective: number;
  category: string;
  as_of: string;
  assets: Asset[];
  findings: Finding[];
  paths: { items: PathItem[]; truncated: boolean };
  summary: {
    assets: number;
    findings: number;
    high_risk: number;
    paths: number;
    critical_assets_reachable: number;
  };
  graph: {
    nodes: { id: string; node_type: string; name?: string; title?: string }[];
    edges: { source: string; target: string; key: string; type: string }[];
  };
  assumptions: string[];
};
type Plan = {
  budget: number;
  cost: number;
  method: string;
  plan: {
    kind: string;
    target_id: string;
    label: string;
    cost: number;
    impact: string;
  }[];
  simulation: Simulation | null;
};
type Simulation = {
  before: { risk: number; objective: number; summary: { paths: number } };
  after: { risk: number; objective: number; summary: { paths: number } };
  risk_reduction: number;
  objective_reduction: number;
  removed_paths: string[];
  warning: string;
  truncated: boolean;
};
type Project = { id: string; name: string; has_data?: boolean };
const nav = [
  { name: "Overview", icon: LayoutDashboard },
  { name: "Risk Graph", icon: Network },
  { name: "Assets", icon: Server },
  { name: "Findings", icon: Search },
  { name: "Attack Paths", icon: Route },
  { name: "Remediation", icon: Wrench },
  { name: "CYVRA AI", icon: Sparkles },
];
async function api<T>(path: string, body?: unknown): Promise<T> {
  const r = await fetch("/api/" + path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json();
  if (!r.ok)
    throw new Error(
      typeof data.detail === "string"
        ? data.detail
        : JSON.stringify(data.detail),
    );
  return data;
}
function Badge({ category }: { category: string }) {
  return <span className={"badge " + category}>{category}</span>;
}
export default function Dashboard() {
  const [tab, setTab] = useState("Overview"),
    [projects, setProjects] = useState<Project[]>([]),
    [project, setProject] = useState(""),
    [analysis, setAnalysis] = useState<Analysis | null>(null),
    [plan, setPlan] = useState<Plan | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [query, setQuery] = useState(""),
    [selected, setSelected] = useState<Finding | null>(null),
    [simulation, setSimulation] = useState<Simulation | null>(null),
    [budget, setBudget] = useState(3),
    [question, setQuestion] = useState("What should I fix first?"),
    [answer, setAnswer] = useState<{
      answer: string;
      citations: string[];
      provider: string;
    } | null>(null);
  const refresh = useCallback(async (id: string) => {
    const a = await api<Analysis>("projects/" + id + "/analysis");
    setAnalysis(a);
    setProjects((v) =>
      v.map((p) => (p.id === id ? { ...p, has_data: true } : p)),
    );
    setSelected(null);
    setSimulation(null);
    setAnswer(null);
    setPlan(
      await api<Plan>("projects/" + id + "/recommendations", { budget: 3 }),
    );
  }, []);
  useEffect(() => {
    api<Project[]>("projects")
      .then(setProjects)
      .catch((e) => setError(e.message));
  }, []);
  async function run(work: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await work();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }
  async function create(demo: boolean) {
    await run(async () => {
      const name = demo
        ? "Aurora · Synthetic lab"
        : window.prompt("Environment name");
      if (!name) return;
      const p = await api<Project>("projects", { name });
      setProjects((v) => [...v, { ...p, has_data: false }]);
      setProject(p.id);
      setAnalysis(null);
      setPlan(null);
      if (demo) {
        await api("projects/" + p.id + "/demo", {});
        await refresh(p.id);
      }
    });
  }
  async function switchProject(id: string) {
    setProject(id);
    setAnalysis(null);
    setPlan(null);
    setSelected(null);
    setSimulation(null);
    if (id && projects.find((p) => p.id === id)?.has_data !== false)
      await run(() => refresh(id));
  }
  async function loadDemo() {
    await run(async () => {
      await api("projects/" + project + "/demo", {});
      await refresh(project);
    });
  }
  async function importFile(file: File) {
    if (file.size > 2000000) {
      setError("Maximum upload is 2 MB");
      return;
    }
    await run(async () => {
      await api(
        "projects/" + project + "/import",
        JSON.parse(await file.text()),
      );
      await refresh(project);
    });
  }
  function download() {
    run(async () => {
      const data = await api("projects/" + project + "/dataset");
      const url = URL.createObjectURL(
        new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.download = "cyvra-dataset.json";
      link.click();
      URL.revokeObjectURL(url);
      return;
    });
  }
  async function simulateActions(
    actions: { kind: string; target_id: string }[],
  ) {
    await run(async () =>
      setSimulation(
        await api<Simulation>("projects/" + project + "/simulate", { actions }),
      ),
    );
  }
  const filtered =
    analysis?.findings.filter((f) =>
      (f.title + " " + f.id + " " + f.asset_name)
        .toLowerCase()
        .includes(query.toLowerCase()),
    ) || [];
  const nodes =
    analysis?.graph.nodes.map((n, i) => ({
      id: n.id,
      position: { x: (i % 4) * 250, y: Math.floor(i / 4) * 150 },
      data: { label: n.name || n.title || n.id },
      style: {
        background: n.node_type === "FINDING" ? "#37211f" : "#102928",
        color: "#e7f3f0",
        border: "1px solid #36514c",
        borderRadius: 10,
        width: 210,
        padding: 12,
      },
    })) || [];
  const edges =
    analysis?.graph.edges.map((e) => ({
      id: e.key,
      source: e.source,
      target: e.target,
      label: e.type,
      markerEnd: { type: MarkerType.ArrowClosed },
      style: { stroke: "#659d8e" },
      labelStyle: { fill: "#b7c8c3", fontSize: 10 },
      labelBgStyle: { fill: "#101b1b" },
    })) || [];
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <Shield size={31} />
          <span>
            CYVRA<small>RISK INTELLIGENCE</small>
          </span>
        </div>
        <div className="workspace">
          <span className="eyebrow">WORKSPACE</span>
          <strong>Research workspace</strong>
          <span className="muted">Local · single user</span>
        </div>
        <nav>
          {nav.map(({ name, icon: Icon }) => (
            <button
              key={name}
              className={tab === name ? "active" : ""}
              onClick={() => setTab(name)}
            >
              <Icon size={18} />
              {name}
              {name === "CYVRA AI" && <span className="tiny">OFFLINE</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <span className="status-dot" /> Defensive analysis only
          <p>
            Evidence over speculation.
            <br />
            Human decisions remain central.
          </p>
          <div className="version">
            CYVRA MVP <span>v0.1.0</span>
          </div>
        </div>
      </aside>
      <div className="content">
        <header>
          <div className="breadcrumb">
            Workspace <ChevronRight size={14} />
            <span>{tab}</span>
          </div>
          <div className="header-right">
            <span className="status-dot" /> Analytical engines
            <span className="avatar">MK</span>
          </div>
        </header>
        <main>
          <div className="title-row">
            <div>
              <div className="eyebrow">CYBER VULNERABILITY & RISK ANALYSIS</div>
              <h1>{tab}</h1>
              <p className="muted">
                Turn fragmented evidence into clear security decisions.
              </p>
            </div>
            <div className="actions">
              <select
                aria-label="Select environment"
                value={project}
                disabled={busy}
                onChange={(e) => switchProject(e.target.value)}
              >
                <option value="">Select environment</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
              <button disabled={busy} onClick={() => create(false)}>
                <Plus size={16} />
                Environment
              </button>
              <button
                className="primary"
                disabled={busy}
                onClick={() => create(true)}
              >
                Launch demo <ArrowUpRight size={16} />
              </button>
            </div>
          </div>
          {error && (
            <div className="error" role="alert">
              {error}
            </div>
          )}
          {busy && (
            <div className="loading" role="status">
              Analyzing supplied evidence…
            </div>
          )}
          {project && (
            <div className="toolbar">
              <label className={"button " + (busy ? "disabled" : "")}>
                <Upload size={15} /> Import JSON
                <input
                  disabled={busy}
                  type="file"
                  accept=".json,application/json"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) importFile(f);
                    e.target.value = "";
                  }}
                />
              </label>
              <button disabled={busy} onClick={loadDemo}>
                Load synthetic dataset
              </button>
              <button disabled={busy || !analysis} onClick={download}>
                <Download size={15} />
                Export data
              </button>
              <span className="muted">
                Import replaces this environment’s dataset.
              </span>
            </div>
          )}
          {!analysis ? (
            <section className="empty">
              <div className="empty-icon">
                <Network size={50} />
              </div>
              <span className="eyebrow">EVIDENCE → CONTEXT → DECISIONS</span>
              <h2>Understand what matters. Know what to fix.</h2>
              <p>
                Launch Aurora, a fictional SaaS environment, to explore
                contextual risks, potential paths to critical assets, and
                defensive remediation simulations.
              </p>
              <button
                className="primary"
                disabled={busy}
                onClick={() => create(true)}
              >
                Explore the synthetic lab <ArrowUpRight size={16} />
              </button>
              <div className="empty-features">
                <span>Transparent risk factors</span>
                <span>Evidence confidence</span>
                <span>Counterfactual simulation</span>
              </div>
            </section>
          ) : (
            <>
              {tab === "Overview" && (
                <>
                  <div className="stats">
                    <section className="card risk-card">
                      <div className="card-label">
                        MODELED CYBER RISK <Activity size={16} />
                      </div>
                      <div className="risk-number">
                        {analysis.risk.toFixed(0)}
                        <small>/100</small>
                        <Badge category={analysis.category} />
                      </div>
                      <div className="meter">
                        <span style={{ width: analysis.risk + "%" }} />
                      </div>
                      <p>Maximum critical finding or possible path</p>
                    </section>
                    {[
                      {
                        label: "HIGH PRIORITY FINDINGS",
                        value: analysis.summary.high_risk,
                        note: `of ${analysis.summary.findings} findings`,
                        icon: Search,
                      },
                      {
                        label: "POTENTIAL ATTACK PATHS",
                        value: analysis.summary.paths,
                        note: "Connectivity hypotheses · not attacks",
                        icon: Route,
                      },
                      {
                        label: "REACHABLE CRITICAL ASSETS",
                        value: analysis.summary.critical_assets_reachable,
                        note: `across ${analysis.summary.assets} assets`,
                        icon: Server,
                      },
                    ].map((s) => (
                      <section className="card" key={s.label}>
                        <div className="card-label">
                          {s.label}
                          <s.icon size={16} />
                        </div>
                        <div className="stat-number">{s.value}</div>
                        <p>{s.note}</p>
                      </section>
                    ))}
                  </div>
                  <div className="overview-grid">
                    <section className="card recommendation">
                      <div className="section-title">
                        <span>
                          <span className="status-dot" /> RECOMMENDED NEXT STEP
                        </span>
                        <Wrench size={18} />
                      </div>
                      <h2>
                        {plan?.plan[0]?.label || "No improving action found"}
                      </h2>
                      <p className="muted">
                        Greedy plan under a {plan?.budget || 3}-unit
                        illustrative budget. Review operational impact before
                        making real changes.
                      </p>
                      <div className="projection">
                        <div>
                          <span>CURRENT RISK</span>
                          <strong>
                            {plan?.simulation?.before.risk ?? analysis.risk}
                          </strong>
                        </div>
                        <span className="projection-arrow">→</span>
                        <div>
                          <span>AFTER FULL PLAN</span>
                          <strong className="green">
                            {plan?.simulation?.after.risk ?? analysis.risk}
                          </strong>
                        </div>
                      </div>
                      <button
                        className="primary"
                        disabled={busy || !plan?.plan.length}
                        onClick={() => simulateActions(plan!.plan)}
                      >
                        Simulate full plan <ArrowUpRight size={16} />
                      </button>
                      <button onClick={() => setTab("Remediation")}>
                        Review actions
                      </button>
                    </section>
                    <section className="card">
                      <div className="section-title">
                        <h3>Evidence & uncertainty</h3>
                        <span className="tiny">TRANSPARENT</span>
                      </div>
                      <p className="muted">
                        Confidence reflects provenance, freshness, agreement,
                        and missing fields. It is separate from risk.
                      </p>
                      {analysis.findings.slice(0, 3).map((f) => (
                        <div className="confidence-row" key={f.id}>
                          <div>
                            <strong>{f.asset_name}</strong>
                            <span>
                              {f.missing.length
                                ? `${f.missing.length} missing context fields`
                                : "Context fields provided"}
                            </span>
                          </div>
                          <span>{f.confidence.toFixed(0)}%</span>
                          <div className="confidence-meter">
                            <span style={{ width: f.confidence + "%" }} />
                          </div>
                        </div>
                      ))}
                    </section>
                  </div>
                  <section className="card">
                    <div className="section-title">
                      <h3>Prioritized findings</h3>
                      <button onClick={() => setTab("Findings")}>
                        View all <ArrowUpRight size={14} />
                      </button>
                    </div>
                    {findingTable(analysis.findings.slice(0, 5))}
                  </section>
                </>
              )}
              {tab === "Findings" && (
                <section className="card">
                  <div className="section-title">
                    <h3>Findings ranked by contextual risk</h3>
                    <input
                      aria-label="Search findings"
                      placeholder="Search findings or assets…"
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                    />
                  </div>
                  {findingTable(filtered)}
                </section>
              )}
              {tab === "Risk Graph" && (
                <section className="card">
                  <div className="section-title">
                    <h3>Cyber risk graph</h3>
                    <span className="muted">
                      Drag nodes · zoom · inspect relationships
                    </span>
                  </div>
                  <div className="graph">
                    <ReactFlow
                      nodes={nodes}
                      edges={edges}
                      fitView
                      colorMode="dark"
                      onNodeClick={(_, n) => {
                        const f = analysis.findings.find((f) => f.id === n.id);
                        if (f) setSelected(f);
                      }}
                    >
                      <Background />
                      <Controls />
                      <MiniMap nodeColor="#477a6d" />
                    </ReactFlow>
                  </div>
                  <p className="muted">
                    Asset connectivity and AFFECTED_BY findings. Connectivity
                    alone does not prove an exploit chain.
                  </p>
                </section>
              )}
              {tab === "Assets" && (
                <section className="card">
                  <h3>Asset inventory</h3>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Asset</th>
                          <th>Type</th>
                          <th>Criticality</th>
                          <th>Exposure</th>
                          <th>Owner</th>
                        </tr>
                      </thead>
                      <tbody>
                        {analysis.assets.map((a) => (
                          <tr key={a.id}>
                            <td>
                              <strong>{a.name}</strong>
                              <small>{a.id}</small>
                            </td>
                            <td>{a.type}</td>
                            <td>{Math.round(a.criticality * 100)}%</td>
                            <td>
                              <Badge
                                category={a.internet_exposed ? "high" : "low"}
                              />
                              <small>
                                {a.internet_exposed
                                  ? "Public entry"
                                  : "Internal"}
                              </small>
                            </td>
                            <td>{a.owner}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}
              {tab === "Attack Paths" && (
                <section className="card">
                  <h3>Potential paths toward critical assets</h3>
                  <p className="muted">
                    Bounded search: six hops, 200 paths, 10,000 expansions.
                    Inferred edges remain unconfirmed.
                  </p>
                  {analysis.paths.truncated && (
                    <div className="error">
                      Search truncated. Counts and simulations are incomplete.
                    </div>
                  )}
                  {analysis.paths.items.map((p) => (
                    <div className="path-card" key={p.id}>
                      <div className="section-title">
                        <strong>
                          {p.nodes
                            .map(
                              (id) =>
                                analysis.assets.find((a) => a.id === id)
                                  ?.name || id,
                            )
                            .join(" → ")}
                        </strong>
                        <span className="score">{p.risk}</span>
                      </div>
                      <p>
                        Possible connectivity path · {p.confidence.toFixed(0)}%
                        confidence ·{" "}
                        {p.inferred
                          ? "includes inferred relationship"
                          : "relationships marked observed"}
                      </p>
                      <small>
                        Supporting findings: {p.finding_ids.join(", ")}
                      </small>
                    </div>
                  ))}
                  {!analysis.paths.items.length && (
                    <p>
                      No paths supported by open findings within configured
                      bounds.
                    </p>
                  )}
                </section>
              )}
              {tab === "Remediation" && (
                <section className="card">
                  <div className="section-title">
                    <h3>Counterfactual remediation lab</h3>
                    <div className="actions">
                      <label>
                        Budget{" "}
                        <input
                          aria-label="Remediation budget"
                          className="budget"
                          type="number"
                          min="1"
                          max="10"
                          value={budget}
                          onChange={(e) => setBudget(Number(e.target.value))}
                        />
                      </label>
                      <button
                        disabled={busy || budget < 1 || budget > 10}
                        className="primary"
                        onClick={() =>
                          run(async () =>
                            setPlan(
                              await api<Plan>(
                                "projects/" + project + "/recommendations",
                                { budget },
                              ),
                            ),
                          )
                        }
                      >
                        Optimize plan
                      </button>
                    </div>
                  </div>
                  <p className="muted">
                    Illustrative cost units, not currency. These controls
                    simulate changes only.
                  </p>
                  {plan?.plan.map((r, i) => (
                    <div className="path-card" key={r.kind + r.target_id}>
                      <div className="section-title">
                        <h3>
                          {i + 1}. {r.label}
                        </h3>
                        <button
                          disabled={busy}
                          onClick={() => simulateActions([r])}
                        >
                          Simulate action
                        </button>
                      </div>
                      <p>
                        Cost: {r.cost} · Operational impact: {r.impact}
                      </p>
                    </div>
                  ))}
                  <button
                    className="primary"
                    disabled={busy || !plan?.plan.length}
                    onClick={() => simulateActions(plan!.plan)}
                  >
                    Simulate combined plan
                  </button>
                  <p className="muted">
                    {plan?.method} · Total cost {plan?.cost}/{plan?.budget}
                  </p>
                </section>
              )}
              {tab === "CYVRA AI" && (
                <section className="card copilot">
                  <Sparkles className="green" size={30} />
                  <h2>Ask your evidence.</h2>
                  <p className="muted">
                    Offline structured explanation provider. No external AI API
                    or generated threat intelligence.
                  </p>
                  <div className="prompt-options">
                    {[
                      "What should I fix first?",
                      "Why is risk high?",
                      "Which paths reach critical assets?",
                    ].map((q) => (
                      <button key={q} onClick={() => setQuestion(q)}>
                        {q}
                      </button>
                    ))}
                  </div>
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      run(async () =>
                        setAnswer(
                          await api("projects/" + project + "/explain", {
                            question,
                          }),
                        ),
                      );
                    }}
                  >
                    <input
                      aria-label="Ask CYVRA"
                      maxLength={2000}
                      value={question}
                      onChange={(e) => setQuestion(e.target.value)}
                    />
                    <button disabled={busy || !question} className="primary">
                      Ask CYVRA
                    </button>
                  </form>
                  {answer && (
                    <div className="answer">
                      <p>{answer.answer}</p>
                      <span className="eyebrow">STRUCTURED CITATIONS</span>
                      <p>
                        {answer.citations.join(" · ") ||
                          "No evidence referenced"}
                      </p>
                      <small>Provider: {answer.provider}</small>
                    </div>
                  )}
                </section>
              )}
              {simulation && (
                <section className="card simulation" aria-live="polite">
                  <div className="section-title">
                    <h3>Simulation results</h3>
                    <button onClick={() => setSimulation(null)}>Dismiss</button>
                  </div>
                  <div className="simulation-grid">
                    <div>
                      <span>MODELED RISK</span>
                      <strong>
                        {simulation.before.risk} → {simulation.after.risk}
                      </strong>
                    </div>
                    <div>
                      <span>OBJECTIVE REDUCTION</span>
                      <strong>
                        {simulation.objective_reduction.toFixed(1)}
                      </strong>
                    </div>
                    <div>
                      <span>PATHS REMOVED</span>
                      <strong>{simulation.removed_paths.length}</strong>
                    </div>
                  </div>
                  <p className="muted">{simulation.warning}</p>
                  {simulation.truncated && (
                    <p className="error">
                      Path search truncated; results may be incomplete.
                    </p>
                  )}
                </section>
              )}
              {selected && (
                <section className="card detail">
                  <div className="section-title">
                    <h3>
                      {selected.id}: {selected.title}
                    </h3>
                    <button onClick={() => setSelected(null)}>
                      Close details
                    </button>
                  </div>
                  <p>{selected.explanation}</p>
                  <div className="factor-grid">
                    {Object.entries(selected.contributions).map(([k, v]) => (
                      <div key={k}>
                        <span>{k.replaceAll("_", " ")}</span>
                        <strong>+{v.toFixed(1)}</strong>
                      </div>
                    ))}
                  </div>
                  <h3>Source evidence</h3>
                  {selected.evidence.map((e) => (
                    <p key={e.id}>
                      <strong>{e.id}</strong> · {e.source} ·{" "}
                      {new Date(e.collected_at).toLocaleDateString()} ·
                      reliability {e.reliability} ·{" "}
                      {e.supports ? "supporting" : "contradictory"}
                    </p>
                  ))}
                  <p className="muted">
                    Missing context: {selected.missing.join(", ") || "none"}
                  </p>
                  <button
                    disabled={busy || selected.status === "resolved"}
                    className="primary"
                    onClick={() =>
                      simulateActions([
                        { kind: "patch", target_id: selected.id },
                      ])
                    }
                  >
                    Simulate patch
                  </button>
                </section>
              )}
              <footer>
                <Shield size={14} /> Modeled risk, not breach probability.{" "}
                {analysis.as_of.slice(0, 10)} · Model v0.1.0 · Synthetic data is
                labeled.
              </footer>
            </>
          )}
        </main>
      </div>
    </div>
  );
  function findingTable(items: Finding[]) {
    return (
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Finding / Asset</th>
              <th>CVSS</th>
              <th>Modeled risk</th>
              <th>Confidence</th>
              <th>Priority</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {items.map((f) => (
              <tr key={f.id}>
                <td>
                  <strong>{f.title}</strong>
                  <small>
                    {f.id} · {f.asset_name} · {f.status}
                  </small>
                </td>
                <td>{f.cvss.toFixed(1)}</td>
                <td>
                  <span className="score">{f.risk.toFixed(1)}</span>
                </td>
                <td>
                  {f.confidence.toFixed(0)}%
                  <small>{f.missing.length} missing fields</small>
                </td>
                <td>
                  <Badge category={f.category} />
                </td>
                <td>
                  <button
                    aria-label={"Explain " + f.id}
                    onClick={() => setSelected(f)}
                  >
                    Why? <ChevronRight size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!items.length && <p>No matching findings.</p>}
      </div>
    );
  }
}
