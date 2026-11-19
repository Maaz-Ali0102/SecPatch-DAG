import { StrictMode, useEffect, useRef, useState, type FormEvent } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";
import { MaintenanceStudy } from "./MaintenanceStudy";
import { GraphView } from "./graph";
import { Assets, History, Optimization, Overview, Vulnerabilities, type Readiness } from "./views";
import { gsap, useGSAP, reducedMotion, Modal } from "./ui";
import type { Analysis, Asset, Comparison, Environment, Estimates, InventoryRow, Project, Summary, Tab } from "./types";

const API = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000/api/v1";
const demoVulnerabilityId = "OSV-DEMO-2026-0001";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, { headers: { "Content-Type": "application/json" }, ...init });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(errorText(body.detail) ?? `Request failed (${response.status})`);
  return body as T;
}
function errorText(detail: unknown): string | undefined {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((item) => String(item?.msg ?? item).replace(/^Value error, /, "")).join("; ");
  return undefined;
}
async function readJson(file: File): Promise<any> {
  try { return JSON.parse(await file.text()); } catch { throw new Error(`${file.name} is not a valid JSON file`); }
}
function download(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const anchor = document.createElement("a"); anchor.href = url; anchor.download = name; anchor.click(); URL.revokeObjectURL(url);
}
function csvCell(cell: string) { const text = /^[=+\-@\t\r]/.test(cell) ? `'${cell}` : cell; return `"${text.split('"').join('""')}"`; }
function csv(rows: string[][]) { return rows.map((row) => row.map((cell) => csvCell(String(cell))).join(",")).join("\n"); }

const NAV: Array<{ key: Tab; label: string; group: "Plan" | "Review"; icon: string }> = [
  { key: "overview", label: "Overview", group: "Plan", icon: "M4 11l8-6 8 6v8a1 1 0 01-1 1h-4v-5H9v5H5a1 1 0 01-1-1z" },
  { key: "assets", label: "Servers & inventory", group: "Plan", icon: "M4 5h16v5H4zM4 14h16v5H4zM7.5 7.5h.01M7.5 16.5h.01" },
  { key: "vulnerabilities", label: "Advisories", group: "Plan", icon: "M12 3l9 16H3zM12 10v4M12 17h.01" },
  { key: "graph", label: "Dependency graph", group: "Plan", icon: "M6 6h.01M18 6h.01M12 18h.01M6 6l6 12M18 6l-6 12M6 6h12" },
  { key: "optimization", label: "Compare plans", group: "Plan", icon: "M4 19V9M10 19V5M16 19v-7M22 19H2" },
  { key: "history", label: "History", group: "Review", icon: "M12 7v5l3 2M3 12a9 9 0 109-9 9 9 0 00-7 3.3M3 4v4h4" },
  { key: "cep", label: "Two-window study", group: "Review", icon: "M3 6h8v12H3zM13 6h8v12h-8z" },
];

function Icon({ d }: { d: string }) {
  return <svg viewBox="0 0 24 24" aria-hidden="true" className="nav-icon"><path d={d} /></svg>;
}

function App() {
  const [tab, setTab] = useState<Tab>("overview");
  const [projects, setProjects] = useState<Project[]>([]), [project, setProject] = useState<Project | null>(null);
  const [environments, setEnvironments] = useState<Environment[]>([]), [environment, setEnvironment] = useState<Environment | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]), [inventory, setInventory] = useState<InventoryRow[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null), [comparison, setComparison] = useState<Comparison | null>(null);
  const [graphAnalysis, setGraphAnalysis] = useState<Analysis | null>(null), [envGraph, setEnvGraph] = useState<Analysis | null>(null);
  const [confirm, setConfirm] = useState<{ title: string; text: string; action: () => Promise<void> } | null>(null);
  const [history, setHistory] = useState<Analysis[]>([]), [windowMinutes, setWindowMinutes] = useState(60);
  const [duration, setDuration] = useState(15), [benefit, setBenefit] = useState(90), [, setCandidateId] = useState("");
  const [estimateFile, setEstimateFile] = useState<{ name: string; values: Estimates } | null>(null);
  const [loading, setLoading] = useState(false), [error, setError] = useState(""), [apiState, setApiState] = useState("checking");
  const [notice, setNotice] = useState("");
  const [showProject, setShowProject] = useState(false), [showEnvironment, setShowEnvironment] = useState(false), [showAsset, setShowAsset] = useState(false), [editAsset, setEditAsset] = useState<Asset | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);

  const shellRef = useRef<HTMLDivElement>(null);
  const navRef = useRef<HTMLElement>(null);
  const indicatorRef = useRef<HTMLSpanElement>(null);

  useEffect(() => { if (error) window.scrollTo({ top: 0, behavior: "smooth" }); }, [error]);
  useEffect(() => { if (!notice) return; const t = setTimeout(() => setNotice(""), 4200); return () => clearTimeout(t); }, [notice]);
  const refreshProjects = async () => { const values = await request<Project[]>("/projects"); setProjects(values); };
  const checkApi = () => request("/health").then(() => setApiState("online")).catch(() => setApiState("offline"));
  useEffect(() => { refreshProjects().catch((e: Error) => setError(e.message)); checkApi(); }, []);

  // Number keys 1–7 jump between pages when focus is not in a field.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (e.metaKey || e.ctrlKey || e.altKey || ["INPUT", "SELECT", "TEXTAREA"].includes(t.tagName)) return;
      const i = Number(e.key) - 1;
      if (i >= 0 && i < NAV.length) { setTab(NAV[i].key); setMenuOpen(false); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Sliding marker behind the active navigation item, and a short entrance for each page.
  useGSAP(() => {
    const active = navRef.current?.querySelector<HTMLElement>('[aria-current="page"]');
    if (active && indicatorRef.current) gsap.to(indicatorRef.current, { y: active.offsetTop, height: active.offsetHeight, autoAlpha: 1, duration: reducedMotion() ? 0 : 0.45, ease: "power3.inOut" });
    if (!reducedMotion()) gsap.from(".page > .page-stack > *", { y: 14, opacity: 0, duration: 0.5, stagger: 0.06, clearProps: "transform,opacity" });
  }, { scope: shellRef, dependencies: [tab] });
  useGSAP(() => {
    if (reducedMotion()) return;
    gsap.from(".brand, .workspace, .nav-group", { x: -12, opacity: 0, stagger: 0.07, duration: 0.6, clearProps: "transform,opacity" });
  }, { scope: shellRef });
  useGSAP(() => { if (!reducedMotion()) gsap.from(".toast, .alert", { y: -10, opacity: 0, duration: 0.35 }); }, { scope: shellRef, dependencies: [notice, error] });

  const selectEnvironment = async (value: Environment, projectId = project?.id) => {
    setEnvironment(value); setAnalysis(null); setComparison(null); setGraphAnalysis(null); setEnvGraph(null); if (!projectId) return;
    // Reload stored candidates so analyses never run with an empty estimate set after a refresh or switch.
    setSummary(await request<Summary>(`/environments/${value.id}/candidates`));
    const projectAssets = await request<Asset[]>(`/environments/${value.id}/assets`);
    setAssets(projectAssets);
    const rows = (await Promise.all(projectAssets.map((asset) => request<InventoryRow[]>(`/assets/${asset.id}/inventory`)))).flat(); setInventory(rows);
    const runs = await request<Array<Analysis & { id?: string }>>(`/projects/${projectId}/analysis-runs?environment_id=${value.id}`);
    setHistory(runs.map((run) => ({ ...run, run_id: run.run_id ?? run.id })));
    setEnvGraph(await request<Analysis>(`/environments/${value.id}/graph`));
  };
  const selectProject = async (value: Project) => { setProject(value); setEnvironment(null); setEnvironments([]); setAssets([]); setInventory([]); setSummary(null); setHistory([]); setEnvGraph(null); setAnalysis(null); setComparison(null); const envs = await request<Environment[]>(`/projects/${value.id}/environments`); setEnvironments(envs); if (envs[0]) await selectEnvironment(envs[0], value.id); };
  const submitProject = async (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); const f = new FormData(event.currentTarget); setLoading(true); try { const created = await request<Project>("/projects", { method: "POST", body: JSON.stringify({ name: f.get("name"), description: f.get("description") || null }) }); await refreshProjects(); await selectProject(created); setShowProject(false); setNotice(`Project "${created.name}" created`); } catch (e) { setError(e instanceof Error ? e.message : "Unable to create project"); } finally { setLoading(false); } };
  const submitEnvironment = async (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); if (!project) return; const f = new FormData(event.currentTarget); setLoading(true); try { const created = await request<Environment>("/environments", { method: "POST", body: JSON.stringify({ project_id: project.id, name: f.get("name"), description: f.get("description") || null }) }); setEnvironments(await request<Environment[]>(`/projects/${project.id}/environments`)); await selectEnvironment(created, project.id); setShowEnvironment(false); setNotice(`Environment "${created.name}" created`); } catch (e) { setError(e instanceof Error ? e.message : "Unable to create environment"); } finally { setLoading(false); } };
  const importInventory = async (file: File) => { if (!environment) throw new Error("Select an environment first"); const value = await readJson(file); if (!Array.isArray(value.packages)) throw new Error("Inventory JSON must contain a packages array"); await request("/inventory", { method: "POST", body: JSON.stringify({ environment_id: environment.id, packages: value.packages }) }); await selectEnvironment(environment); setNotice(`Imported ${value.packages.length} packages from ${file.name}`); };
  const importVulnerabilities = async (file: File) => { if (!environment) throw new Error("Select an environment first"); const osv = await readJson(file); if (!Array.isArray(osv.vulns)) throw new Error("OSV JSON must contain a vulns array"); if (!inventory.length) throw new Error("This environment has no installed packages yet. Import the inventory first, then the OSV file, so vulnerabilities can be matched."); const payload = { packages: inventory.map((row) => ({ asset_id: assets.find((asset) => asset.id === row.asset_id)?.external_identifier, ecosystem: row.ecosystem, name: row.package, version: row.version })) }; const result = await request<Summary>("/vulnerabilities/import", { method: "POST", body: JSON.stringify({ environment_id: environment.id, osv, inventory: payload }) }); setSummary(result); if (result?.candidate_details[0]) setCandidateId(result.candidate_details[0].candidate_key ?? result.candidate_details[0].id); setNotice(`Checked ${osv.vulns.length} advisories · ${result.candidate_details.length} candidates`); };
  const importDependencies = async (file: File) => {
    if (!environment) throw new Error("Select an environment first");
    const value = await readJson(file);
    const edges = Array.isArray(value) ? value : value.dependencies;
    if (!Array.isArray(edges)) throw new Error("Dependencies JSON must contain a dependencies array");
    setEnvGraph(await request<Analysis>("/dependencies", { method: "POST", body: JSON.stringify({ environment_id: environment.id, dependencies: edges }) }));
    setGraphAnalysis(null); setAnalysis(null); setComparison(null);
    setNotice(`Imported ${edges.length} dependencies`);
  };
  const clearWorkspace = () => { setEnvironment(null); setAssets([]); setInventory([]); setSummary(null); setHistory([]); setEnvGraph(null); setAnalysis(null); setComparison(null); setGraphAnalysis(null); };
  const askDeleteProject = () => project && setConfirm({ title: `Delete project "${project.name}"?`, text: "The project, its environments and servers disappear from the dashboard and the name can be reused. Saved plans stay in the database as an audit record.", action: async () => { await request(`/projects/${project.id}`, { method: "DELETE" }); setProject(null); setEnvironments([]); clearWorkspace(); await refreshProjects(); } });
  const askDeleteEnvironment = () => project && environment && setConfirm({ title: `Delete environment "${environment.name}"?`, text: "Its servers and inventory are removed from the dashboard. Saved plans stay in the database as an audit record.", action: async () => { await request(`/environments/${environment.id}`, { method: "DELETE" }); clearWorkspace(); const envs = await request<Environment[]>(`/projects/${project.id}/environments`); setEnvironments(envs); if (envs[0]) await selectEnvironment(envs[0], project.id); } });
  const askDeleteAsset = (asset: Asset) => environment && setConfirm({ title: `Delete server "${asset.name}"?`, text: "Its inventory and vulnerabilities leave new analyses and its identifier can be reused. Past plans in History are kept.", action: async () => { await request(`/assets/${asset.id}`, { method: "DELETE" }); await selectEnvironment(environment); } });
  const actionable = summary?.candidate_details.filter((candidate) => candidate.applicability === "affected" && candidate.unresolved_issues.length === 0 && candidate.candidate_key) ?? [];
  const estimates = () => {
    if (estimateFile) return estimateFile.values;
    if (!Number.isInteger(duration) || duration <= 0 || !Number.isInteger(benefit) || benefit < 0) throw new Error("Duration must be a positive whole number and benefit a whole number of zero or more");
    if (actionable.length) return Object.fromEntries(actionable.map((candidate) => [candidate.candidate_key, { duration_minutes: duration, benefit, priority: benefit }]));
    throw new Error("No actionable candidates in this environment. Import inventory and OSV data first, or upload an estimates file.");
  };
  const run = async (comparisonId: string, method: "cp_sat" | "precedence_greedy" | "dynamic_programming") => { if (!project || !environment) throw new Error("Select a project and an environment in the left sidebar first."); return request<Analysis>("/persisted-plans", { method: "POST", body: JSON.stringify({ project_id: project.id, environment_id: environment.id, window_minutes: windowMinutes, method, comparison_id: comparisonId, estimate_source: estimateFile?.name ?? "Manual estimates", estimates: estimates() }) }); };
  const runComparison = async () => { setLoading(true); setError(""); try { const comparisonId = crypto.randomUUID(); const greedy = await run(comparisonId, "precedence_greedy"); const dp = await run(comparisonId, "dynamic_programming"); const cp_sat = await run(comparisonId, "cp_sat"); if (greedy && dp && cp_sat) { setComparison({ greedy, dp, cp_sat }); setAnalysis(dp.optimization?.solver_status === "OPTIMAL" ? dp : cp_sat); setNotice("Comparison saved to history"); if (project && environment) { const runs = await request<Array<Analysis & { id?: string }>>(`/projects/${project.id}/analysis-runs?environment_id=${environment.id}`); setHistory(runs.map((item) => ({ ...item, run_id: item.run_id ?? item.id }))); } } } catch (e) { setError(e instanceof Error ? e.message : "Comparison failed"); } finally { setLoading(false); } };
  const importEstimates = async (file: File) => {
    const value = await readJson(file);
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Estimates JSON must be an object keyed by <asset external identifier>:<vulnerability id>");
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      const entry = item as { duration_minutes?: unknown; benefit?: unknown } | null;
      if (!entry || typeof entry !== "object" || !Number.isInteger(entry.duration_minutes) || !Number.isInteger(entry.benefit)) throw new Error(`Estimate ${key} needs whole-number duration_minutes and benefit`);
    }
    setEstimateFile({ name: file.name, values: value as Estimates });
    setNotice(`Loaded ${Object.keys(value).length} estimates from ${file.name}`);
  };
  const openHistory = async (id: string) => { setLoading(true); try { const saved = await request<Analysis>(`/analysis-runs/${id}`); setComparison(null); setAnalysis(saved); setTab("optimization"); } catch (e) { setError(e instanceof Error ? e.message : "Unable to load analysis"); } finally { setLoading(false); } };
  const exportAnalysis = () => analysis && download("secpatch-analysis.json", JSON.stringify(analysis, null, 2), "application/json");
  const exportPlan = () => analysis && download("secpatch-remediation-plan.csv", csv([["Action", "Package", "Start", "Finish", "Duration", "Benefit"], ...(analysis.schedule?.entries ?? []).map((entry) => { const action = analysis.optimization?.selected_actions?.find((item) => item.id === entry.action_id); return [entry.action_id, action?.package_id ?? "", String(entry.start_minute), String(entry.finish_minute), String(entry.duration_minutes), String(action?.benefit ?? "")]; })]), "text/csv");
  const exportComparison = () => comparison && download("secpatch-comparison.csv", csv([["Method", "Status", "Objective", "Duration", "Selected actions", "Optimality"], ...(["greedy", "dp", "cp_sat"] as const).map((method) => { const result = comparison[method]; return [method, result.optimization?.solver_status ?? "", String(result.optimization?.objective_value ?? 0), String(result.schedule?.total_duration_minutes ?? 0), String(result.optimization?.selected_actions?.length ?? 0), String(Boolean(result.optimization?.optimality_proven))]; })]), "text/csv");
  const setupDemo = async () => {
    setLoading(true); setError("");
    try {
      const suffix = new Date().toISOString().slice(11, 19).replace(/:/g, "");
      const createdProject = await request<Project>("/projects", { method: "POST", body: JSON.stringify({ name: `SecPatch demo ${suffix}`, description: "Synthetic offline demonstration data" }) });
      const createdEnvironment = await request<Environment>("/environments", { method: "POST", body: JSON.stringify({ project_id: createdProject.id, name: "Production-like lab" }) });
      await request("/assets", { method: "POST", body: JSON.stringify({ environment_id: createdEnvironment.id, name: "API host", external_identifier: "asset-api", operating_system: "linux" }) });
      await request("/assets", { method: "POST", body: JSON.stringify({ environment_id: createdEnvironment.id, name: "Worker host", external_identifier: "asset-worker", operating_system: "linux" }) });
      await request("/inventory", { method: "POST", body: JSON.stringify({ environment_id: createdEnvironment.id, packages: [{ asset_id: "asset-api", ecosystem: "PyPI", name: "demo-lib", version: "1.9" }, { asset_id: "asset-worker", ecosystem: "PyPI", name: "demo-lib", version: "1.10.0" }] }) });
      const vulnerability = await request<Summary>("/vulnerabilities/import", { method: "POST", body: JSON.stringify({ environment_id: createdEnvironment.id, osv: { vulns: [{ id: demoVulnerabilityId, aliases: ["CVE-2026-0001"], summary: "Synthetic demo vulnerability", affected: [{ package: { ecosystem: "PyPI", name: "demo-lib" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.0.0" }, { fixed: "1.10.0" }] }] }] }] }, inventory: { packages: [{ asset_id: "asset-api", ecosystem: "PyPI", name: "demo-lib", version: "1.9" }, { asset_id: "asset-worker", ecosystem: "PyPI", name: "demo-lib", version: "1.10.0" }] } }) });
      const graphResult = await request<Analysis>("/plans", { method: "POST", body: JSON.stringify({ dataset: { packages: [{ id: "web-gateway" }, { id: "auth-service" }, { id: "shared-crypto" }, { id: "payments" }, { id: "billing" }, { id: "ledger" }], dependencies: [{ from: "web-gateway", to: "auth-service" }, { from: "auth-service", to: "shared-crypto" }, { from: "payments", to: "shared-crypto" }, { from: "payments", to: "billing" }, { from: "billing", to: "ledger" }, { from: "ledger", to: "billing" }], actions: [{ id: "patch-crypto", package_id: "shared-crypto", duration_minutes: 20, benefit: 95, priority: 95 }, { id: "patch-auth", package_id: "auth-service", duration_minutes: 25, benefit: 80, priority: 85, prerequisites: ["patch-crypto"] }, { id: "patch-payments", package_id: "payments", duration_minutes: 10, benefit: 70, priority: 70 }] }, window_minutes: windowMinutes, method: "cp_sat" }) });
      await refreshProjects(); await selectProject(createdProject); setSummary(vulnerability); setCandidateId(`asset-api:${demoVulnerabilityId}`); setGraphAnalysis(graphResult); setTab("overview");
      setNotice("Demo workspace ready");
    } catch (e) { setError(e instanceof Error ? e.message : "Demo setup failed"); } finally { setLoading(false); }
  };

  const go = (t: Tab) => { setTab(t); setMenuOpen(false); window.scrollTo({ top: 0 }); };
  const fail = (fallback: string) => (e: unknown) => setError(e instanceof Error ? e.message : fallback);
  const selected = analysis?.optimization?.selected_actions ?? [];
  const graphSource = graphAnalysis ?? envGraph ?? analysis;
  const ready: Readiness = {
    workspace: !!environment, assets: assets.length, inventory: inventory.length,
    advisories: summary?.package_checks ? summary.package_checks.length : summary?.candidate_details.length ? summary.candidate_details.length : null,
    affected: summary?.package_checks?.filter((r) => r.status === "affected").length ?? actionable.length,
    edges: graphSource?.graph?.edges?.length ?? 0, runs: history.length,
  };
  const badge: Partial<Record<Tab, string | number>> = { assets: assets.length || "", vulnerabilities: ready.affected || "", graph: (graphSource?.graph?.blocked_packages?.length ?? 0) ? "!" : "", history: history.length || "" };
  const current = NAV.find((n) => n.key === tab)!;

  return <div className={`shell ${menuOpen ? "menu-open" : ""}`} ref={shellRef}>
    <a className="skip" href="#main">Skip to content</a>
    <aside className="sidebar">
      <div className="brand">
        <svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" /><path d="M9 22l7-12 7 12" /><circle cx="16" cy="22" r="2" /></svg>
        <div><b>SecPatch</b><small>patch window planner</small></div>
        <button className="icon-btn menu-btn" aria-label={menuOpen ? "Close menu" : "Open menu"} aria-expanded={menuOpen} onClick={() => setMenuOpen(!menuOpen)}>{menuOpen ? "×" : "≡"}</button>
      </div>

      <div className="workspace">
        <label><span>Project</span>
          <select value={project?.id ?? ""} onChange={(e) => { const value = projects.find((item) => item.id === e.target.value); if (value) selectProject(value).catch(fail("Unable to load project")); }}>
            <option value="">Choose a project…</option>{projects.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select>
        </label>
        <label><span>Environment</span>
          <select value={environment?.id ?? ""} disabled={!project} onChange={(e) => { const value = environments.find((item) => item.id === e.target.value); if (value && project) selectEnvironment(value, project.id).catch(fail("Unable to load environment")); }}>
            <option value="">{project ? (environments.length ? "Choose an environment…" : "No environments yet") : "Pick a project first"}</option>{environments.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select>
        </label>
        <div className="ws-actions">
          <button className="btn ghost sm" onClick={() => setShowProject(true)}>+ Project</button>
          <button className="btn ghost sm" disabled={!project} onClick={() => setShowEnvironment(true)}>+ Environment</button>
          {project && <details className="ws-more"><summary className="btn ghost sm" aria-label="More workspace actions">⋯</summary>
            <div className="ws-menu"><button onClick={askDeleteProject}>Delete project</button><button disabled={!environment} onClick={askDeleteEnvironment}>Delete environment</button></div>
          </details>}
        </div>
      </div>

      <nav ref={navRef} aria-label="Pages">
        <span className="nav-indicator" ref={indicatorRef} aria-hidden="true" />
        {(["Plan", "Review"] as const).map((group) => <div className="nav-group" key={group}>
          <span className="nav-title">{group}</span>
          {NAV.filter((n) => n.group === group).map((n) => <button key={n.key} aria-current={tab === n.key ? "page" : undefined} onClick={() => go(n.key)}>
            <Icon d={n.icon} /><span>{n.label}</span>
            {badge[n.key] ? <em className={n.key === "graph" ? "warn" : n.key === "vulnerabilities" ? "bad" : ""}>{badge[n.key]}</em> : <kbd>{NAV.indexOf(n) + 1}</kbd>}
          </button>)}
        </div>)}
      </nav>

      <button className={`api ${apiState}`} onClick={checkApi} title="Click to check again"><i />API {apiState}</button>
    </aside>

    <main className="main" id="main">
      <header className="topbar">
        <div className="crumbs"><span>{project?.name ?? "No project"}</span><i>/</i><span>{environment?.name ?? "no environment"}</span><i>/</i><b>{current.label}</b></div>
        {(!environment || tab === "overview") && <button className="btn ghost sm" onClick={setupDemo} disabled={loading}>{loading ? "Preparing…" : "Load demo workspace"}</button>}
      </header>
      {error && <div className="alert" role="alert"><b>That didn't work</b><span>{error}</span><button className="icon-btn" aria-label="Dismiss" onClick={() => setError("")}>×</button></div>}
      {notice && <div className="toast" role="status"><i />{notice}</div>}
      <div className="page" key={tab}>
        {tab === "overview" && <Overview ready={ready} analysis={analysis} selected={selected} windowMinutes={windowMinutes} navigate={go} onDemo={setupDemo} loading={loading} envName={environment ? `${project?.name} / ${environment.name}` : undefined} />}
        {tab === "assets" && <Assets hasEnv={!!environment} assets={assets} inventory={inventory} onCreate={() => setShowAsset(true)} onEdit={setEditAsset} onDelete={askDeleteAsset} onImport={(file) => importInventory(file).catch(fail("Inventory import failed"))} />}
        {tab === "vulnerabilities" && <Vulnerabilities canImport={!!environment} summary={summary} onImport={(file) => importVulnerabilities(file).catch(fail("OSV import failed"))} />}
        {tab === "graph" && <GraphView analysis={graphSource} canImport={!!environment} onImport={(file) => importDependencies(file).catch(fail("Dependency import failed"))} />}
        {tab === "optimization" && <Optimization actionable={actionable.length} analysis={analysis} comparison={comparison} windowMinutes={windowMinutes} setWindowMinutes={setWindowMinutes} duration={duration} setDuration={setDuration} benefit={benefit} setBenefit={setBenefit} run={runComparison} loading={loading} exportAnalysis={exportAnalysis} exportPlan={exportPlan} exportComparison={exportComparison} estimateFile={estimateFile?.name ?? null} onEstimateFile={(file) => importEstimates(file).catch(fail("Estimates import failed"))} clearEstimateFile={() => setEstimateFile(null)} />}
        {tab === "cep" && <MaintenanceStudy key={analysis?.run_id} api={API} runId={analysis?.run_id} />}
        {tab === "history" && <History runs={history} open={openHistory} />}
      </div>
    </main>

    {confirm && <ConfirmDialog {...confirm} onClose={() => setConfirm(null)} onError={setError} />}
    {showProject && <WorkspaceForm title="New project" nameLimit={200} onSubmit={submitProject} onClose={() => setShowProject(false)} busy={loading} />}
    {showEnvironment && <WorkspaceForm title={`New environment in ${project?.name}`} nameLimit={120} onSubmit={submitEnvironment} onClose={() => setShowEnvironment(false)} busy={loading} />}
    {showAsset && environment && <AssetForm environmentId={environment.id} onDone={(name) => { setNotice(`Server "${name}" registered`); selectEnvironment(environment).catch(fail("Reload failed")); }} onError={setError} onClose={() => setShowAsset(false)} />}
    {editAsset && environment && <AssetForm environmentId={environment.id} asset={editAsset} onDone={(name) => { setNotice(`Server "${name}" saved`); selectEnvironment(environment).catch(fail("Reload failed")); }} onError={setError} onClose={() => setEditAsset(null)} />}
  </div>;
}

function ConfirmDialog({ title, text, action, onClose, onError }: { title: string; text: string; action: () => Promise<void>; onClose: () => void; onError: (message: string) => void }) {
  const [busy, setBusy] = useState(false);
  const go = async () => { setBusy(true); try { await action(); onClose(); } catch (error) { onError(error instanceof Error ? error.message : "Delete failed"); onClose(); } finally { setBusy(false); } };
  return <Modal title={title} onClose={onClose}>
    <p className="muted">{text}</p>
    <div className="modal-actions"><button type="button" className="btn ghost" onClick={onClose} autoFocus>Cancel</button><button type="button" className="btn danger" disabled={busy} onClick={go}>{busy ? "Deleting…" : "Delete"}</button></div>
  </Modal>;
}
function WorkspaceForm({ title, nameLimit, onSubmit, onClose, busy }: { title: string; nameLimit: number; onSubmit: (e: FormEvent<HTMLFormElement>) => void; onClose: () => void; busy: boolean }) {
  return <Modal title={title} onClose={onClose} onSubmit={onSubmit}>
    <label className="field">Name<input name="name" required maxLength={nameLimit} autoFocus /></label>
    <label className="field">Description <small>optional</small><input name="description" maxLength={2000} /></label>
    <div className="modal-actions"><button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy}>Create</button></div>
  </Modal>;
}
function AssetForm({ environmentId, asset, onDone, onError, onClose }: { environmentId: string; asset?: Asset; onDone: (name: string) => void; onError: (message: string) => void; onClose: () => void }) {
  const submit = async (e: FormEvent<HTMLFormElement>) => { e.preventDefault(); const f = new FormData(e.currentTarget); const body = { name: String(f.get("name") ?? "").trim(), external_identifier: String(f.get("external_identifier") ?? "").trim(), operating_system: String(f.get("operating_system") ?? "").trim() }; try { if (asset) { await request(`/assets/${asset.id}`, { method: "PATCH", body: JSON.stringify(body) }); } else { await request("/assets", { method: "POST", body: JSON.stringify({ environment_id: environmentId, ...body, operating_system: body.operating_system || null }) }); } onDone(body.name); onClose(); } catch (error) { onError(error instanceof Error ? error.message : asset ? "Unable to update asset" : "Unable to register asset"); } };
  return <Modal title={asset ? "Edit server" : "Register server"} onClose={onClose} onSubmit={submit}>
    <label className="field">Name<input name="name" required maxLength={200} defaultValue={asset?.name ?? ""} autoFocus placeholder="API host" /></label>
    <label className="field">Identifier <small>must match asset_id in the inventory file</small><input name="external_identifier" required maxLength={255} defaultValue={asset?.external_identifier ?? ""} placeholder="asset-api-prod" /></label>
    {asset && <p className="muted small">Inventory stays linked to this server. Changing the identifier changes its estimate keys (identifier:vulnerability).</p>}
    <label className="field">Operating system <small>optional</small><input name="operating_system" maxLength={120} defaultValue={asset?.operating_system ?? ""} placeholder="linux" /></label>
    <div className="modal-actions"><button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn primary">{asset ? "Save changes" : "Register"}</button></div>
  </Modal>;
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
