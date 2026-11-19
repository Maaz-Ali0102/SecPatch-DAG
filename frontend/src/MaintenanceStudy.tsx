import { useRef, useState, type FormEvent } from "react";
import { gsap, useGSAP, reducedMotion, Card, Empty, PageHead } from "./ui";

type WindowPlan = { capacity: number; minutes: number; schedule: { action_id: string; start_minute: number; finish_minute: number }[] };
type Plan = { benefit: number | null; status: string; windows: WindowPlan[]; rebuilt_groups: string[][]; reused_groups: string[][] };
type Study = { baseline: Plan; sensitivity: Plan; incremental: Plan; removed: string[]; full_ms: number; incremental_ms: number; added_dependencies: string[][] };

function WindowTrack({ w, index }: { w: WindowPlan; index: number }) {
  const cap = Math.max(w.capacity, w.minutes, 1);
  return <div className="win">
    <div className="win-head"><span>Window {index + 1}</span><b>{w.minutes}<small>/{w.capacity} min</small></b></div>
    <div className="win-track">
      {w.schedule.map((x) => <div key={x.action_id} className="win-seg" style={{ left: `${(x.start_minute / cap) * 100}%`, width: `${((x.finish_minute - x.start_minute) / cap) * 100}%` }} title={`${x.action_id} · ${x.start_minute}–${x.finish_minute} min`}>
        <span>{x.action_id.replace(/^patch-/, "")}</span>
      </div>)}
      {!w.schedule.length && <span className="win-empty">No patches fit</span>}
    </div>
  </div>;
}

function Scenario({ title, plan, note, best }: { title: string; plan: Plan; note?: string; best: number }) {
  const delta = plan.benefit != null ? plan.benefit - best : null;
  return <article className="scenario">
    <header><div><h4>{title}</h4>{note && <small>{note}</small>}</div>
      <div className="scenario-score"><b>{plan.benefit ?? "—"}</b><small>benefit{delta ? ` · ${delta > 0 ? "+" : ""}${delta}` : ""}</small></div></header>
    {plan.windows.map((w, i) => <WindowTrack key={i} w={w} index={i} />)}
  </article>;
}

export function MaintenanceStudy({ api, runId }: { api: string; runId?: string }) {
  const [study, setStudy] = useState<Study>();
  const [savedPlan, setSavedPlan] = useState<Plan>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [source, setSource] = useState<"demo" | "saved">("demo");
  const ref = useRef<HTMLDivElement>(null);

  useGSAP(() => {
    if (reducedMotion()) return;
    const tl = gsap.timeline();
    tl.from(".scenario", { y: 14, opacity: 0, stagger: 0.12, duration: 0.5 })
      .from(".win-seg", { scaleX: 0, transformOrigin: "left center", stagger: 0.03, duration: 0.45 }, "-=0.2");
  }, { scope: ref, dependencies: [study, savedPlan], revertOnUpdate: true });

  async function run(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    setBusy(true); setError(""); setStudy(undefined); setSavedPlan(undefined);
    try {
      const query = new URLSearchParams({ first: String(fields.get("first")), second: String(fields.get("second")) });
      const saved = source === "saved" && runId;
      const path = saved ? "/analysis-runs/" + runId + "/maintenance-windows" : "/cep/experiment";
      const response = await fetch(api + path + "?" + query);
      if (!response.ok) throw new Error((await response.json()).detail || "Could not run planner");
      const data = await response.json();
      if (saved) setSavedPlan(data); else setStudy(data);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not reach backend");
    } finally { setBusy(false); }
  }

  const base = study?.baseline.benefit ?? 0;
  return <div className="page-stack" ref={ref}>
    <PageHead title="Two maintenance windows" lead="Each patch must fit entirely inside one window. See what the exact planner picks, then what changes when a patch is retired or new dependencies appear." />
    <Card>
      <form className="study-form" onSubmit={run}>
        <div className="segmented" role="radiogroup" aria-label="Input">
          <button type="button" role="radio" aria-checked={source === "demo"} aria-selected={source === "demo"} onClick={() => setSource("demo")}>Worked dataset · 12 packages</button>
          <button type="button" role="radio" aria-checked={source === "saved"} aria-selected={source === "saved"} disabled={!runId} onClick={() => setSource("saved")} title={runId ? "" : "Run or open a comparison first"}>Current analysis</button>
        </div>
        <label>First window<span className="unit-input"><input required type="number" name="first" min="0" max="1440" defaultValue="18" /><small>min</small></span></label>
        <label>Second window<span className="unit-input"><input required type="number" name="second" min="0" max="1440" defaultValue="13" /><small>min</small></span></label>
        <button className="btn primary" disabled={busy}>{busy ? <><span className="spinner" /> Planning…</> : "Plan both windows"}</button>
      </form>
      {error && <p className="form-error" role="alert">{error}</p>}
    </Card>

    {savedPlan && <div className="scenarios"><Scenario title={`Current analysis · ${savedPlan.status}`} plan={savedPlan} best={savedPlan.benefit ?? 0} /></div>}
    {study && <>
      <div className="scenarios">
        <Scenario title="Baseline" plan={study.baseline} note="All patches available" best={base} />
        <Scenario title="After removal" plan={study.sensitivity} note={`Retires ${study.removed.join(" and ")}`} best={base} />
        <Scenario title="After dependency changes" plan={study.incremental} note={`Adds ${study.added_dependencies.map((e) => e.join(" → ")).join(", ")}`} best={base} />
      </div>
      <Card title="Incremental rebuild">
        <div className="mini-stats">
          <div><b>{study.incremental.rebuilt_groups.length}</b><span>groups rebuilt</span></div>
          <div><b>{study.incremental.reused_groups.length}</b><span>groups reused</span></div>
          <div><b>{study.incremental_ms}<small> ms</small></b><span>incremental</span></div>
          <div><b>{study.full_ms}<small> ms</small></b><span>full rebuild</span></div>
        </div>
        <p className="muted small">Only the dependency groups touched by the new edges are planned again. Both approaches produce the same assignment.</p>
      </Card>
    </>}
    {!study && !savedPlan && !busy && <Empty title="Choose two window lengths" text="18 and 13 minutes reproduce the worked example: 82, 78 and 71 benefit points." />}
  </div>;
}
