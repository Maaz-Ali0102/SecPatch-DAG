import { useMemo, useRef, useState } from "react";
import { gsap, useGSAP, reducedMotion, Card, Chip, Empty, FileDrop, PageHead, Stat } from "./ui";
import type { Analysis } from "./types";

const W = 168, H = 54, COL = 236, ROW = 82, PAD = 36;

/** Layered layout: prerequisites on the left, the packages that depend on them to the right. */
function layout(nodes: string[], edges: Array<{ from: string; to: string }>, cycles: string[][] = []) {
  const comp = new Map<string, number>(); cycles.forEach((c, i) => c.forEach((n) => comp.set(n, i)));
  const level = new Map(nodes.map((n) => [n, 0]));
  for (let pass = 0; pass < nodes.length; pass++) {
    let changed = false;
    for (const e of edges) {
      if (e.from === e.to || (comp.has(e.from) && comp.get(e.from) === comp.get(e.to))) continue;
      const want = (level.get(e.to) ?? 0) + 1;
      if (want > (level.get(e.from) ?? 0) && want < nodes.length) { level.set(e.from, want); changed = true; }
    }
    if (!changed) break;
  }
  const columns = new Map<number, string[]>();
  for (const n of nodes) { const l = level.get(n) ?? 0; columns.set(l, [...(columns.get(l) ?? []), n]); }
  const used = [...columns.keys()].sort((a, b) => a - b);
  const pos = new Map<string, { x: number; y: number }>();
  const tallest = Math.max(1, ...[...columns.values()].map((c) => c.length));
  used.forEach((l, ci) => {
    const col = columns.get(l)!;
    const offset = ((tallest - col.length) * ROW) / 2;
    col.forEach((n, ri) => pos.set(n, { x: PAD + ci * COL, y: PAD + offset + ri * ROW }));
  });
  // Extra right margin: edges between packages in the same column (cycles) curve out to the right of it.
  return { pos, width: PAD * 2 + Math.max(0, used.length - 1) * COL + W + 64, height: PAD * 2 + (tallest - 1) * ROW + H };
}

function edgePath(a: { x: number; y: number }, b: { x: number; y: number }, bend: number, self: boolean) {
  if (self) return `M${a.x + W - 30},${a.y} c 10,-34 46,-30 30,${H / 2}`;
  const ay = a.y + H / 2 + bend, by = b.y + H / 2 + bend;
  if (a.x > b.x) { const sx = a.x, ex = b.x + W, mid = (sx - ex) / 2; return `M${sx},${ay} C${sx - mid},${ay} ${ex + mid},${by} ${ex + 6},${by}`; }
  if (a.x < b.x) { const sx = a.x + W, ex = b.x, mid = (ex - sx) / 2; return `M${sx},${ay} C${sx + mid},${ay} ${ex - mid},${by} ${ex - 6},${by}`; }
  const x = a.x + W; return `M${x},${ay} C${x + 70},${ay} ${x + 70},${by} ${x + 6},${by}`;
}

export function GraphView({ analysis, canImport, onImport }: { analysis: Analysis | null; canImport: boolean; onImport: (file: File) => void }) {
  const graph = analysis?.graph;
  const nodes = graph?.nodes ?? [];
  const edges = graph?.edges ?? [];
  const blocked = graph?.blocked_packages ?? graph?.dependency_analysis?.analysis?.blocked_nodes ?? [];
  const blockedSet = new Set(blocked);
  const cyclic = graph?.cyclic_components ?? [];
  const cyclicSet = new Set(cyclic.flat());
  const order = (graph?.topological_order ?? []).filter((n) => !blockedSet.has(n));
  const [view, setView] = useState<"graph" | "order">("graph");
  const [zoom, setZoom] = useState(1);
  const [focus, setFocus] = useState("");
  const [selected, setSelected] = useState("");
  const { pos, width, height } = useMemo(() => layout(nodes, edges, cyclic), [nodes.join("|"), edges.map((e) => e.from + ">" + e.to).join("|"), cyclic.length]);
  const svgRef = useRef<HTMLDivElement>(null);
  const active = focus || selected;
  const linked = (e: { from: string; to: string }) => !!active && (e.from === active || e.to === active);

  useGSAP(() => {
    if (reducedMotion() || view !== "graph") return;
    const paths = gsap.utils.toArray<SVGPathElement>(".edge");
    paths.forEach((p) => { const len = p.getTotalLength(); gsap.fromTo(p, { strokeDasharray: len, strokeDashoffset: len }, { strokeDashoffset: 0, duration: 0.9, delay: 0.25, ease: "power2.inOut", clearProps: "strokeDasharray,strokeDashoffset" }); });
    gsap.from(".node-body", { opacity: 0, scale: 0.85, transformOrigin: "50% 50%", duration: 0.45, stagger: 0.035, ease: "back.out(1.6)" });
    gsap.from(".order-row", { opacity: 0, x: -10, stagger: 0.04 });
  }, { scope: svgRef, dependencies: [nodes.join("|"), edges.length, view], revertOnUpdate: true });

  const nodeState = (n: string) => cyclicSet.has(n) ? "cycle" : blockedSet.has(n) ? "blocked" : "ok";
  const sel = selected && {
    needs: edges.filter((e) => e.from === selected && e.to !== selected).map((e) => e.to),
    neededBy: edges.filter((e) => e.to === selected && e.from !== selected).map((e) => e.from),
    position: order.indexOf(selected),
  };

  return <div className="page-stack">
    <PageHead title="Dependency graph" lead="Which packages must be patched before others. Arrows point at the prerequisite, so the left column goes first. Packages caught in a cycle are held back from the plan."
      actions={<div className="segmented" role="tablist">
        <button role="tab" aria-selected={view === "graph"} onClick={() => setView("graph")}>Graph</button>
        <button role="tab" aria-selected={view === "order"} onClick={() => setView("order")}>Patch order</button>
      </div>} />
    <div className="stat-row">
      <Stat label="Packages" value={nodes.length} />
      <Stat label="Dependencies" value={edges.length} />
      <Stat label="Cycles found" value={cyclic.length} tone={cyclic.length ? "bad" : ""} note="Tarjan SCC" />
      <Stat label="Blocked packages" value={blocked.length} tone={blocked.length ? "warn" : ""} note="held out of plans" />
    </div>
    <div className="graph-layout" ref={svgRef}>
      <Card className="graph-card" title={view === "graph" ? "Package map" : "Prerequisite-first order"} meta={view === "graph" ? "Hover a package to trace it, click to pin" : "Kahn topological sort on the SCC condensation"}
        actions={view === "graph" && nodes.length > 0 && <div className="zoom">
          <button className="icon-btn" aria-label="Zoom out" onClick={() => setZoom(Math.max(0.6, +(zoom - 0.15).toFixed(2)))}>−</button>
          <span>{Math.round(zoom * 100)}%</span>
          <button className="icon-btn" aria-label="Zoom in" onClick={() => setZoom(Math.min(1.8, +(zoom + 0.15).toFixed(2)))}>+</button>
          <button className="btn ghost sm" onClick={() => setZoom(1)}>Reset</button>
        </div>}>
        {view === "order" ? <div className="order-list">
          {order.length ? order.map((n, i) => <button key={n} className={`order-row ${selected === n ? "sel" : ""}`} onClick={() => setSelected(n)}><span>{String(i + 1).padStart(2, "0")}</span><b>{n}</b><Chip tone="ok">ready</Chip></button>)
            : <Empty title={blocked.length ? "Every package is blocked" : "Nothing to order yet"} text={blocked.length ? "Break the dependency cycle to schedule these packages." : "Import dependencies to compute a patch order."} />}
          {blocked.length > 0 && <div className="blocked-list"><h4>Held back by a cycle</h4>{blocked.map((n) => <div key={n} className="order-row blocked"><span>—</span><b>{n}</b><Chip tone={cyclicSet.has(n) ? "bad" : "warn"}>{cyclicSet.has(n) ? "in cycle" : "depends on cycle"}</Chip></div>)}</div>}
        </div> : nodes.length ? <div className="graph-viewport">
          <svg width={width * zoom} height={height * zoom} viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Dependency graph" className={active ? "has-focus" : ""}>
            <defs>
              <marker id="arrow" markerWidth="9" markerHeight="9" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" /></marker>
              <marker id="arrow-hot" markerWidth="9" markerHeight="9" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" /></marker>
            </defs>
            {edges.map((e, i) => {
              const a = pos.get(e.from), b = pos.get(e.to); if (!a || !b) return null;
              const back = edges.some((o) => o.from === e.to && o.to === e.from) && e.from !== e.to;
              const bend = back ? (e.from < e.to ? -7 : 7) : 0;
              const cyc = cyclicSet.has(e.from) && cyclicSet.has(e.to);
              return <path key={i} d={edgePath(a, b, bend, e.from === e.to)} className={`edge ${cyc ? "cyc" : ""} ${linked(e) ? "hot" : ""}`} markerEnd={linked(e) ? "url(#arrow-hot)" : "url(#arrow)"} />;
            })}
            {nodes.map((n) => {
              const p = pos.get(n)!; const st = nodeState(n);
              const label = n.length > 21 ? n.slice(0, 20) + "…" : n;
              const dim = active && active !== n && !edges.some((e) => (e.from === active && e.to === n) || (e.to === active && e.from === n));
              return <g key={n} transform={`translate(${p.x},${p.y})`} className={`node ${st} ${selected === n ? "sel" : ""} ${dim ? "dim" : ""}`}
                tabIndex={0} role="button" aria-label={`${n}, ${st === "ok" ? "schedulable" : st}`}
                onMouseEnter={() => setFocus(n)} onMouseLeave={() => setFocus("")} onFocus={() => setFocus(n)} onBlur={() => setFocus("")}
                onClick={() => setSelected(selected === n ? "" : n)} onKeyDown={(ev) => (ev.key === "Enter" || ev.key === " ") && setSelected(selected === n ? "" : n)}>
                <g className="node-body">
                  <title>{n}</title>
                  <rect width={W} height={H} rx="9" />
                  <circle cx="16" cy={H / 2} r="4.5" />
                  <text x="30" y="23" className="n-name">{label}</text>
                  <text x="30" y="40" className="n-sub">{st === "cycle" ? "in a cycle" : st === "blocked" ? "blocked by cycle" : order.includes(n) ? `step ${order.indexOf(n) + 1}` : "package"}</text>
                </g>
              </g>;
            })}
          </svg>
        </div> : <Empty title="No dependency data yet" text={canImport ? "Import a dependencies file to draw the graph." : "Select an environment, then import its dependencies."} />}
        {view === "graph" && nodes.length > 0 && <div className="legend"><span><i className="lg ok" />Schedulable</span><span><i className="lg cycle" />In a cycle</span><span><i className="lg blocked" />Blocked by a cycle</span><span><i className="lg arrow" />Points at the prerequisite</span></div>}
      </Card>
      <aside className="graph-side">
        <Card title="Import dependencies">
          <FileDrop label="Drop dependencies JSON" hint={<>or click to browse · replaces this environment's edges</>} onFile={onImport} disabled={!canImport} />
          <pre className="code-hint">{`{"dependencies": [
  {"from": "PyPI:requests",
   "to": "PyPI:urllib3"}
]}`}</pre>
          <p className="muted small"><code>from</code> depends on <code>to</code>, so <code>to</code> is patched first.</p>
        </Card>
        <Card title={sel ? selected : "Package details"} meta={sel ? (nodeState(selected) === "ok" ? `Step ${sel.position + 1} in the patch order` : nodeState(selected) === "cycle" ? "Part of a cycle" : "Blocked downstream of a cycle") : undefined}>
          {sel ? <dl className="kv">
            <dt>Patch first</dt><dd>{sel.needs.length ? sel.needs.join(", ") : "Nothing — no prerequisites"}</dd>
            <dt>Unblocks</dt><dd>{sel.neededBy.length ? sel.neededBy.join(", ") : "No dependents"}</dd>
          </dl> : <p className="muted small">Click a package in the map or the order list to see what it needs and what it unblocks.</p>}
        </Card>
        {cyclic.length > 0 && <Card title="Cycles">
          {cyclic.map((c) => <div key={c.join(",")} className="cycle-row">{c.join(" ↔ ")}</div>)}
        </Card>}
      </aside>
    </div>
  </div>;
}
