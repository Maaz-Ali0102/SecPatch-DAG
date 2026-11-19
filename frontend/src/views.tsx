import { useRef, useState } from "react";
import { gsap, useGSAP, reducedMotion, Bars, Card, Chip, Empty, FileDrop, PageHead, Stat } from "./ui";
import type { Action, Analysis, Asset, Comparison, InventoryRow, PackageCheck, Summary, Tab } from "./types";

export const maxWindow = 1440; // must match MAX_DASHBOARD_WINDOW in core/ingestion/limits.py

export function methodLabel(method?: string) {
  const names: Record<string, string> = { precedence_greedy: "Greedy", dynamic_programming: "Dynamic programming", cp_sat: "CP-SAT" };
  return method ? names[method] ?? method : "Saved analysis";
}
const statusTone = (s?: string) => s === "OPTIMAL" ? "ok" : s === "FEASIBLE" ? "info" : s === "INFEASIBLE" || s === "INVALID PLAN" ? "bad" : s === "NOT_APPLICABLE" ? "neutral" : "warn";

/* ───────── Overview ───────── */

export type Readiness = { workspace: boolean; assets: number; inventory: number; advisories: number | null; affected: number; edges: number; runs: number };

export function Overview({ ready, analysis, selected, windowMinutes, navigate, onDemo, loading, envName }: { ready: Readiness; analysis: Analysis | null; selected: Action[]; windowMinutes: number; navigate: (tab: Tab) => void; onDemo: () => void; loading: boolean; envName?: string }) {
  const steps: Array<{ tab: Tab; n: string; title: string; text: string; done: boolean; fact: string }> = [
    { tab: "assets", n: "01", title: "Register servers", text: "Add each server and import the packages installed on it.", done: ready.inventory > 0, fact: ready.assets ? `${ready.assets} servers · ${ready.inventory} packages` : "No servers yet" },
    { tab: "vulnerabilities", n: "02", title: "Match advisories", text: "Import an OSV file and see which installed versions are affected.", done: ready.advisories !== null, fact: ready.advisories === null ? "Not imported" : `${ready.affected} affected installs` },
    { tab: "graph", n: "03", title: "Check dependencies", text: "Import package relationships to get a safe order and spot cycles.", done: ready.edges > 0, fact: ready.edges ? `${ready.edges} dependencies` : "Optional · none imported" },
    { tab: "optimization", n: "04", title: "Compare plans", text: "Set the window and run Greedy, DP and CP-SAT on the same inputs.", done: ready.runs > 0, fact: ready.runs ? `${ready.runs} saved results` : "No plans yet" },
  ];
  const next = steps.find((s) => !s.done && s.tab !== "graph") ?? steps.find((s) => !s.done);
  const ref = useRef<HTMLDivElement>(null);
  useGSAP(() => {
    if (reducedMotion()) return;
    gsap.from(".step-line i", { scaleX: 0, transformOrigin: "left center", duration: 1.1, delay: 0.2, ease: "power2.inOut" });
  }, { scope: ref, dependencies: [steps.filter((s) => s.done).length], revertOnUpdate: true });
  const doneCount = steps.filter((s) => s.done).length;
  const duration = analysis?.schedule?.total_duration_minutes ?? 0;

  return <div className="page-stack" ref={ref}>
    <section className="hero-panel">
      <div>
        <span className="kicker">{ready.workspace ? envName : "Start here"}</span>
        <h2>Which security fixes fit tonight's maintenance window?</h2>
        <p>SecPatch matches your installed packages against advisories, orders the fixes by their dependencies, and picks the set that removes the most risk in the time you have.</p>
        <div className="hero-actions">
          {ready.workspace && next ? <button className="btn primary" onClick={() => navigate(next.tab)}>Continue: {next.title.toLowerCase()} →</button>
            : ready.workspace ? <button className="btn primary" onClick={() => navigate("optimization")}>Open the latest plan →</button>
            : <button className="btn primary" onClick={onDemo} disabled={loading}>{loading ? "Preparing demo…" : "Load demo workspace"}</button>}
          <button className="btn ghost" onClick={() => navigate("cep")}>Try the two-window study</button>
        </div>
      </div>
      <div className="progress-ring" aria-label={`${doneCount} of 4 steps complete`}>
        <svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="50" className="ring-bg" /><circle cx="60" cy="60" r="50" className="ring-fg" style={{ strokeDashoffset: 314 - (314 * doneCount) / 4 }} /></svg>
        <div><b>{doneCount}/4</b><small>steps done</small></div>
      </div>
    </section>

    <div className="steps">
      <div className="step-line"><i style={{ width: `${(Math.max(doneCount - 0.5, 0) / 3.5) * 100}%` }} /></div>
      {steps.map((s) => <button key={s.tab} className={`step ${s.done ? "done" : ""} ${next?.tab === s.tab ? "next" : ""}`} onClick={() => navigate(s.tab)}>
        <span className="step-n">{s.done ? "✓" : s.n}</span>
        <b>{s.title}</b>
        <small>{s.text}</small>
        <span className="step-fact">{s.fact}</span>
      </button>)}
    </div>

    {analysis ? <>
      <div className="stat-row">
        <Stat label="Patches selected" value={selected.length} tone="accent" note="latest plan" />
        <Stat label="Minutes used" value={duration} suffix="m" note={`${Math.max(windowMinutes - duration, 0)}m left in the window`} />
        <Stat label="Risk removed" value={analysis.optimization?.objective_value ?? 0} note="benefit points" />
        <Stat label="Solver result" value={analysis.optimization?.solver_status ?? "—"} note={analysis.optimization?.optimality_proven ? "optimal, proven" : "not proven optimal"} tone={statusTone(analysis.optimization?.solver_status)} />
      </div>
      <Schedule analysis={analysis} />
    </> : <Card title="How the planner decides" className="explainer">
      <div className="explain-grid">
        <div><Chip tone="accent">Greedy</Chip><p>Takes the best benefit-per-minute fixes first. Fast; on plain knapsack it gets at least half the best value.</p></div>
        <div><Chip tone="info">Dynamic programming</Chip><p>Exact 0/1 knapsack over minutes. Steps aside when a fix has two or more prerequisites.</p></div>
        <div><Chip tone="ok">CP-SAT</Chip><p>OR-Tools constraint solver. The reference: the only one that can prove a plan optimal.</p></div>
      </div>
    </Card>}
  </div>;
}

/* ───────── Assets ───────── */

export function Assets({ assets, inventory, onCreate, onEdit, onDelete, onImport, hasEnv }: { assets: Asset[]; inventory: InventoryRow[]; onCreate: () => void; onEdit: (a: Asset) => void; onDelete: (a: Asset) => void; onImport: (f: File) => void; hasEnv: boolean }) {
  const [filter, setFilter] = useState("");
  const nameOf = (id?: string) => assets.find((a) => a.id === id)?.name ?? "—";
  const rows = inventory.filter((r) => !filter || `${r.package} ${r.ecosystem} ${r.version} ${nameOf(r.asset_id)}`.toLowerCase().includes(filter.toLowerCase()));
  return <div className="page-stack">
    <PageHead title="Servers and installed software" lead="Register each server with the identifier your inventory file uses, then import what is installed on it."
      actions={<button className="btn primary" onClick={onCreate} disabled={!hasEnv}>+ Register server</button>} />
    <div className="split">
      <Card title="Servers" meta={`${assets.length} registered`}>
        {assets.length ? <div className="asset-list">{assets.map((a) => <article className="asset" key={a.id}>
          <span className="asset-glyph" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="7" rx="2" /><rect x="3" y="13" width="18" height="7" rx="2" /><circle cx="7" cy="7.5" r="1" /><circle cx="7" cy="16.5" r="1" /></svg></span>
          <div><b>{a.name}</b><code>{a.external_identifier ?? "no identifier"}</code><small>{a.operating_system || "OS not given"} · {inventory.filter((r) => r.asset_id === a.id).length} packages</small></div>
          <div className="row-actions"><button className="btn ghost sm" aria-label={`Edit ${a.name}`} onClick={() => onEdit(a)}>Edit</button><button className="btn ghost sm danger-text" aria-label={`Delete ${a.name}`} onClick={() => onDelete(a)}>Delete</button></div>
        </article>)}</div> : <Empty title="No servers registered" text={hasEnv ? "Register a server before importing its inventory." : "Pick a project and environment in the sidebar first."} />}
      </Card>
      <Card title="Import inventory">
        <FileDrop label="Drop inventory JSON" hint="or click to browse · needs a packages array" onFile={onImport} disabled={!hasEnv || !assets.length} />
        <pre className="code-hint">{`{"packages": [{
  "asset_id": "asset-api-prod",
  "ecosystem": "PyPI",
  "name": "requests",
  "version": "2.27.0"
}]}`}</pre>
        <p className="muted small"><code>asset_id</code> must match a server's identifier. Supported versions: PyPI (PEP 440) and npm (SemVer).</p>
      </Card>
    </div>
    <Card title="Package inventory" meta={`${inventory.length} records`} actions={inventory.length > 0 && <input className="search" placeholder="Filter packages…" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter packages" />}>
      {inventory.length ? <div className="table-wrap"><table className="table">
        <thead><tr><th>Package</th><th>Ecosystem</th><th>Version</th><th>Server</th></tr></thead>
        <tbody>{rows.map((r) => <tr key={r.id}><td><b>{r.package ?? "Package"}</b></td><td><Chip>{r.ecosystem ?? "—"}</Chip></td><td className="mono">{r.version ?? "unknown"}</td><td>{nameOf(r.asset_id)}</td></tr>)}</tbody>
      </table>{!rows.length && <p className="muted small pad">No packages match “{filter}”.</p>}</div> : <Empty title="No inventory loaded" text="Import a JSON file with a packages array." />}
    </Card>
  </div>;
}

/* ───────── Vulnerabilities ───────── */

const checkMeta: Record<PackageCheck["status"], { label: string; tone: "bad" | "ok" | "warn" | "neutral" }> = {
  affected: { label: "Affected", tone: "bad" },
  unaffected: { label: "Outside affected ranges", tone: "ok" },
  unknown: { label: "Version needs review", tone: "warn" },
  no_match: { label: "No advisory in file", tone: "neutral" },
};

export function Vulnerabilities({ summary, onImport, canImport }: { summary: Summary | null; onImport: (f: File) => void; canImport: boolean }) {
  const rows = summary?.package_checks;
  const [only, setOnly] = useState<PackageCheck["status"] | "">("");
  const count = (s: PackageCheck["status"]) => rows?.filter((r) => r.status === s).length ?? 0;
  const order: PackageCheck["status"][] = ["affected", "unknown", "unaffected", "no_match"];
  const ref = useRef<HTMLDivElement>(null);
  useGSAP(() => { if (!reducedMotion()) gsap.from(".mix i", { scaleX: 0, transformOrigin: "left center", stagger: 0.1, duration: 0.8 }); }, { scope: ref, dependencies: [rows?.length ?? 0], revertOnUpdate: true });
  const shown = rows?.filter((r) => !only || r.status === only) ?? [];
  const issues = summary?.issues.filter((i) => i.code !== "package_not_in_inventory") ?? [];

  return <div className="page-stack" ref={ref}>
    <PageHead title="Advisories against installed packages" lead="Each installed version is checked against the OSV ranges in the file you import. Unknown versions are flagged for review, never guessed." />
    <div className="split">
      <Card title="Coverage" meta={rows ? `${rows.length} installed packages checked` : "Import advisories to see coverage"}>
        {rows?.length ? <>
          <div className="mix" aria-hidden="true">{order.map((s) => count(s) > 0 && <i key={s} className={checkMeta[s].tone} style={{ flexGrow: count(s) }} />)}</div>
          <div className="mix-legend">{order.map((s) => <button key={s} className={`mix-key ${only === s ? "on" : ""}`} onClick={() => setOnly(only === s ? "" : s)} aria-pressed={only === s}>
            <i className={checkMeta[s].tone} /><b>{count(s)}</b><span>{checkMeta[s].label}</span>
          </button>)}</div>
        </> : <Empty title="No advisories imported" text="Import an OSV file to check every installed version." />}
      </Card>
      <Card title="Import advisories">
        <FileDrop label="Drop OSV JSON" hint={<>or click to browse · try <code>baseline/osv_offline.json</code></>} onFile={onImport} disabled={!canImport} />
        <p className="muted small">Needs a top-level <code>vulns</code> array. Import the inventory first so versions can be matched.</p>
      </Card>
    </div>
    {rows && <Card title="Installed packages" meta={only ? `Showing ${checkMeta[only].label.toLowerCase()} · ${shown.length}` : `${rows.length} results`} actions={only && <button className="btn ghost sm" onClick={() => setOnly("")}>Show all</button>}>
      <div className="table-wrap"><table className="table">
        <thead><tr><th>Server</th><th>Package</th><th>Installed</th><th>Result</th><th>Fixed in</th></tr></thead>
        <tbody>{shown.map((r) => <tr key={JSON.stringify([r.asset, r.ecosystem, r.package, r.version])}>
          <td>{r.asset}</td><td><b>{r.package}</b> <small className="muted">{r.ecosystem}</small></td><td className="mono">{r.version ?? "unknown"}</td>
          <td><Chip tone={checkMeta[r.status].tone}>{checkMeta[r.status].label}</Chip></td><td className="mono">{r.fixes.join(", ") || "—"}</td>
        </tr>)}</tbody>
      </table></div>
    </Card>}
    {summary && <Card title="Remediation candidates" meta={`${summary.candidate_details.length} candidates`}>
      {summary.candidate_details.length ? <div className="cand-list">{summary.candidate_details.map((c) => <div className="cand" key={c.id}>
        <div><b className="mono">{c.vulnerability_id}</b><span>{c.package} · installed <code>{c.installed_version ?? "unknown"}</code> → fixed <code>{c.fixed_version ?? "not given"}</code></span><small>{c.aliases.join(", ") || "No aliases"} · {c.applicability}</small></div>
        <Chip tone={c.unresolved_issues.length ? "warn" : "ok"}>{c.unresolved_issues.length ? "Needs review" : "Actionable"}</Chip>
      </div>)}</div> : <p className="muted small">No candidates to review.</p>}
      {issues.map((i, k) => <div className="issue" key={k}><span>!</span><div><b>{i.code}</b><small>{i.message}</small></div></div>)}
    </Card>}
  </div>;
}

/* ───────── Optimization ───────── */

type OptProps = { analysis: Analysis | null; comparison: Comparison | null; windowMinutes: number; setWindowMinutes: (v: number) => void; duration: number; setDuration: (v: number) => void; benefit: number; setBenefit: (v: number) => void; run: () => void; loading: boolean; exportAnalysis: () => void; exportPlan: () => void; exportComparison: () => void; estimateFile: string | null; onEstimateFile: (f: File) => void; clearEstimateFile: () => void; actionable: number };

export function Optimization(p: OptProps) {
  const { analysis, comparison, windowMinutes, setWindowMinutes } = p;
  const results = comparison ? ([["Greedy", comparison.greedy], ["Dynamic programming", comparison.dp], ["CP-SAT", comparison.cp_sat]] as const) : null;
  return <div className="page-stack">
    <PageHead title="Compare patch plans" lead="Set the time you have, give each fix a duration and a benefit, and run all three algorithms on the same inputs."
      actions={<div className="export-menu">
        <button className="btn ghost sm" onClick={p.exportPlan} disabled={!analysis}>Plan CSV</button>
        <button className="btn ghost sm" onClick={p.exportComparison} disabled={!comparison}>Comparison CSV</button>
        <button className="btn ghost sm" onClick={p.exportAnalysis} disabled={!analysis}>JSON</button>
      </div>} />
    <section className="controls">
      <div className="control">
        <span className="control-n">1</span>
        <div className="control-body">
          <label htmlFor="win"><b>Maintenance window</b></label>
          <div className="window-readout"><input id="win" type="number" min="0" max={maxWindow} value={windowMinutes} onChange={(e) => setWindowMinutes(Math.min(maxWindow, Math.max(0, Math.floor(Number(e.target.value) || 0))))} /><span>minutes</span></div>
          <input type="range" min="0" max={maxWindow} step="5" value={windowMinutes} onChange={(e) => setWindowMinutes(Number(e.target.value))} aria-label="Maintenance window slider" style={{ ["--fill" as string]: `${(windowMinutes / maxWindow) * 100}%` }} />
          <div className="presets">{[30, 60, 120, 240, 480].map((m) => <button key={m} className={windowMinutes === m ? "on" : ""} onClick={() => setWindowMinutes(m)}>{m >= 60 ? `${m / 60}h` : `${m}m`}</button>)}</div>
        </div>
      </div>
      <div className="control">
        <span className="control-n">2</span>
        <div className="control-body">
          <b>Estimates</b>
          <div className="segmented">
            <button aria-selected={!p.estimateFile} onClick={p.clearEstimateFile}>Same for every fix</button>
            <button aria-selected={!!p.estimateFile} onClick={() => document.getElementById("est-file")?.click()}>From a file</button>
          </div>
          {p.estimateFile ? <div className="file-pill"><span className="mono">{p.estimateFile}</span><button className="btn ghost sm" onClick={p.clearEstimateFile}>Remove</button></div> : <div className="pair">
            <label>Minutes per fix<input type="number" min="1" step="1" value={p.duration} onChange={(e) => p.setDuration(Number(e.target.value))} /></label>
            <label>Benefit score<input type="number" min="0" step="1" value={p.benefit} onChange={(e) => p.setBenefit(Number(e.target.value))} /></label>
          </div>}
          <input id="est-file" hidden type="file" accept=".json,application/json" onChange={(e) => { const f = e.target.files?.[0]; if (f) p.onEstimateFile(f); e.target.value = ""; }} />
          <small className="muted">{p.estimateFile ? "Keys are <server id>:<vulnerability id>." : `${p.actionable} actionable fixes will get these values.`}</small>
        </div>
      </div>
      <div className="control run">
        <span className="control-n">3</span>
        <div className="control-body">
          <b>Run</b>
          <p className="muted small">Greedy, dynamic programming and CP-SAT each produce a plan; all three are saved to history.</p>
          <button className="btn primary big" onClick={p.run} disabled={p.loading}>{p.loading ? <><span className="spinner" /> Solving…</> : "Run comparison"}</button>
        </div>
      </div>
    </section>

    {results ? <>
      <div className="split">
        <Card title="Risk removed" meta="benefit points, higher is better">
          <Bars rows={results.map(([label, r]) => ({ label, value: r.optimization?.objective_value ?? 0, tone: r.optimization?.optimality_proven ? "ok" : "accent" }))} />
        </Card>
        <Card title="Window used" meta={`out of ${windowMinutes} minutes`}>
          <Bars max={windowMinutes} unit="m" rows={results.map(([label, r]) => ({ label, value: r.schedule?.total_duration_minutes ?? 0, tone: "ink" }))} />
        </Card>
      </div>
      <div className="result-grid">{results.map(([label, r]) => <ResultCard key={label} title={label} result={r} />)}</div>
    </> : analysis?.optimization ? <ResultCard title={methodLabel(analysis.optimization.method)} result={analysis} />
      : <Empty title="No plans yet" text="Set a window and estimates, then run the comparison." />}

    {analysis?.estimate_review?.ignored && Object.keys(analysis.estimate_review.ignored).length > 0 && <Card title="Estimates that were not used" meta={`${Object.keys(analysis.estimate_review.ignored).length} ignored`}>
      <div className="kv-list">{Object.entries(analysis.estimate_review.ignored).map(([k, why]) => <div key={k}><code>{k}</code><span>{why}</span></div>)}</div>
    </Card>}
    {analysis && <Schedule analysis={analysis} />}
  </div>;
}

function ResultCard({ title, result }: { title: string; result: Analysis }) {
  const o = result.optimization;
  const greedy = o?.method === "precedence_greedy";
  const status = o?.solver_status === "INFEASIBLE" ? "INFEASIBLE" : result.validation?.valid === false ? "INVALID PLAN" : greedy && o?.solver_status === "FEASIBLE" ? (o?.half_bound_applies ? "APPROXIMATION" : "HEURISTIC") : o?.solver_status ?? "UNKNOWN";
  const guarantee = o?.optimality_proven ? "Proven optimal" : o?.half_bound_applies ? "≥ ½ of the best value" : "Not proven";
  return <Card className="result" title={title} actions={<Chip tone={statusTone(status)}>{status}</Chip>}>
    <div className="result-nums">
      <div><span>Benefit</span><b>{o?.objective_value ?? 0}</b></div>
      <div><span>Minutes</span><b>{result.schedule?.total_duration_minutes ?? 0}</b></div>
      <div><span>Fixes</span><b>{o?.selected_actions?.length ?? 0}</b></div>
    </div>
    <p className={`guarantee ${o?.optimality_proven ? "ok" : ""}`}>{guarantee}{o?.runtime_ms != null && <span> · {o.runtime_ms.toFixed(1)} ms</span>}</p>
    <ul className="picked">{(o?.selected_actions ?? []).map((a) => <li key={a.id}><span className="mono">{a.id}</span><small>{a.duration_minutes}m · +{a.benefit}</small></li>)}</ul>
    {(o?.deferred_actions ?? []).length > 0 && <details className="deferred"><summary>{o!.deferred_actions!.length} deferred</summary><p className="mono small">{o!.deferred_actions!.join(", ")}</p></details>}
  </Card>;
}

/* ───────── Schedule ───────── */

export function Schedule({ analysis }: { analysis: Analysis }) {
  const entries = analysis.schedule?.entries ?? [];
  const span = Math.max(analysis.configuration?.window_minutes ?? analysis.window_minutes ?? 0, ...entries.map((e) => e.finish_minute), 1);
  const ref = useRef<HTMLDivElement>(null);
  useGSAP(() => { if (!reducedMotion()) gsap.from(".gantt-bar", { scaleX: 0, transformOrigin: "left center", stagger: 0.07, duration: 0.7 }); }, { scope: ref, dependencies: [analysis.run_id ?? entries.length], revertOnUpdate: true });
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => Math.round(span * f));
  return <div ref={ref}><Card title="Execution schedule" meta={`${analysis.schedule?.total_duration_minutes ?? 0} of ${span} minutes · prerequisites first, then by priority per minute`}>
    {entries.length ? <div className="gantt">
      <div className="gantt-axis"><span />{ticks.map((t, i) => <small key={i} style={{ left: `${(t / span) * 100}%` }}>{t}m</small>)}</div>
      {entries.map((e, i) => <div className="gantt-row" key={e.action_id}>
        <span className="gantt-label"><i>{String(i + 1).padStart(2, "0")}</i><span className="mono">{e.action_id}</span></span>
        <div className="gantt-track"><div className="gantt-bar" style={{ left: `${(e.start_minute / span) * 100}%`, width: `${Math.max((e.duration_minutes / span) * 100, 1.5)}%` }}><small>{e.start_minute}–{e.finish_minute}</small></div></div>
      </div>)}
    </div> : <Empty title="Nothing scheduled" text="No fix fits the window with these estimates." />}
    {analysis.validation?.violations?.map((v) => <div className="issue" key={v}><span>!</span><div><small>{v}</small></div></div>)}
    <details className="trace"><summary>Algorithm trace · {analysis.trace?.length ?? 0} events</summary>
      <ol>{(analysis.trace ?? []).map((ev, i) => <li key={i}><b>{ev.algorithm}</b> {ev.event} <span className="mono">{ev.node ?? ev.action ?? ev.component ?? ""}</span></li>)}</ol>
    </details>
  </Card></div>;
}

/* ───────── History ───────── */

function SavedComparison({ runs, open }: { runs: Analysis[]; open: (id: string) => void }) {
  const first = runs[0];
  const date = first.created_at ? new Date(first.created_at).toLocaleString() : "";
  const best = Math.max(...runs.map((r) => r.objective_value ?? 0));
  return <details className="history-item">
    <summary>
      <span className="h-window"><b>{first.window_minutes ?? "?"}</b><small>min</small></span>
      <span className="h-main"><b>{first.estimate_source ?? "Saved analysis"}</b><small>{date}</small></span>
      <span className="h-meta">{(first.comparison_id || runs.length > 1) ? `${runs.length} of 3 algorithms` : methodLabel(first.method)}</span>
      <span className="h-best">best <b>{best}</b></span>
    </summary>
    <div className="table-wrap"><table className="table">
      <thead><tr><th>Algorithm</th><th>Fixes</th><th>Time used</th><th>Benefit</th><th>Status</th><th /></tr></thead>
      <tbody>{runs.map((r) => <tr key={r.run_id}>
        <td><b>{methodLabel(r.method)}</b></td><td>{r.selected_count ?? "—"}</td><td>{r.used_minutes == null ? "—" : `${r.used_minutes} min`}</td>
        <td><b>{r.objective_value ?? "—"}</b></td><td><Chip tone={statusTone(r.solver_status ?? r.status)}>{r.solver_status ?? r.status}</Chip></td>
        <td><button className="btn ghost sm" onClick={() => r.run_id && open(r.run_id)}>Open →</button></td>
      </tr>)}</tbody>
    </table></div>
  </details>;
}

export function History({ runs, open }: { runs: Analysis[]; open: (id: string) => void }) {
  const earlier: Analysis[][] = [];
  for (let i = 0; i < runs.length; i++) {
    const r = runs[i];
    if (r.comparison_id) continue;
    const trio = runs.slice(i, i + 3);
    const methods = ["cp_sat", "dynamic_programming", "precedence_greedy"];
    const matched = trio.length === 3 && r.window_minutes != null && trio.every((x, j) =>
      !x.comparison_id && x.method === methods[j] && x.window_minutes === r.window_minutes &&
      Math.abs(Date.parse(r.created_at ?? "") - Date.parse(x.created_at ?? "")) <= 2000);
    earlier.push(matched ? trio : [r]);
    if (matched) i += 2;
  }
  const groups = new Map<string, Analysis[]>();
  for (const run of runs) { const key = run.comparison_id; if (!key) continue; groups.set(key, [...(groups.get(key) ?? []), run]); }
  return <div className="page-stack">
    <PageHead title="Analysis history" lead="Every comparison you run is saved with its inputs. Open any result to see its plan and schedule again." />
    {runs.length ? <div className="history-list">
      {Array.from(groups, ([id, g]) => <SavedComparison key={id} runs={g} open={open} />)}
      {earlier.length > 0 && <>
        <h4 className="list-heading">Earlier results <small>grouped by window, save time and algorithm order</small></h4>
        {earlier.map((g) => <SavedComparison key={g[0].run_id} runs={g} open={open} />)}
      </>}
    </div> : <Empty title="No saved comparisons" text="Run a comparison and its results appear here." />}
  </div>;
}
