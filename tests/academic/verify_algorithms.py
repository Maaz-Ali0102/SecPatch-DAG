"""Academic verification of SecPatch-DAG's algorithms.

Every algorithm is checked against an independent reference on randomly
generated instances (fixed seeds, so results are reproducible):

  * Greedy, DP and CP-SAT    vs exhaustive brute force over all 2^n subsets
  * Greedy's 1/2 bound       measured ratio greedy / optimum on plain knapsack
  * Tarjan SCC               vs mutual-reachability SCCs (O(V*(V+E)) reference)
  * Kahn topological order   every edge checked: prerequisite before dependent
  * Blocked nodes            vs reachability to any cyclic component
  * Smith-ratio scheduler    no overlap, inside window, prerequisites first

Run:  python -I tests/academic/verify_algorithms.py
"""
from __future__ import annotations

import itertools
import random
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.graph import analyze_graph  # noqa: E402
from core.models import PatchAction  # noqa: E402
from core.optimization import cp_sat_optimize, dp_optimize, greedy_optimize  # noqa: E402
from core.scheduling import schedule_actions  # noqa: E402

TALLY: dict[str, list[int]] = defaultdict(lambda: [0, 0])
FAILS: list[str] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    TALLY[name][0] += ok
    TALLY[name][1] += 1
    if not ok and len(FAILS) < 25:
        FAILS.append(f"{name}: {detail}")


# ─────────────────────────── knapsack instances ───────────────────────────

def make_actions(rng: random.Random, n: int, shape: str, mandatory: bool) -> dict[str, PatchAction]:
    ids = [f"a{i:02d}" for i in range(n)]
    actions = {}
    for i, aid in enumerate(ids):
        prereqs: tuple[str, ...] = ()
        if i and shape == "forest" and rng.random() < 0.6:
            prereqs = (rng.choice(ids[:i]),)
        elif i and shape == "dag" and rng.random() < 0.6:
            k = rng.randint(1, min(3, i))
            prereqs = tuple(sorted(rng.sample(ids[:i], k)))
        actions[aid] = PatchAction(
            id=aid, package_id=f"p{i}", duration_minutes=rng.randint(1, 40), benefit=rng.randint(0, 100),
            priority=rng.randint(0, 100), prerequisites=prereqs,
            mandatory=mandatory and rng.random() < 0.12)
    return actions


def brute_force(actions: dict[str, PatchAction], window: int, blocked: set[str]) -> int | None:
    ids = list(actions)
    best = None
    for mask in range(1 << len(ids)):
        chosen = {ids[i] for i in range(len(ids)) if mask >> i & 1}
        if chosen & blocked:
            continue
        if any(a.mandatory and a.id not in chosen for a in actions.values()):
            continue
        if any(p not in chosen for a in chosen for p in actions[a].prerequisites):
            continue
        if sum(actions[a].duration_minutes for a in chosen) > window:
            continue
        value = sum(actions[a].benefit for a in chosen)
        best = value if best is None or value > best else best
    return best


def feasible(actions: dict[str, PatchAction], chosen: frozenset[str], window: int, blocked: set[str]) -> bool:
    return (not chosen & blocked
            and all(p in chosen for a in chosen for p in actions[a].prerequisites)
            and sum(actions[a].duration_minutes for a in chosen) <= window)


def knapsack_suite(trials: int) -> list[float]:
    rng = random.Random(2026)
    ratios: list[float] = []
    for t in range(trials):
        shape = ("none", "forest", "dag")[t % 3]
        n = rng.randint(1, 13)
        actions = make_actions(rng, n, shape, mandatory=t % 5 == 4)
        window = rng.randint(0, sum(a.duration_minutes for a in actions.values()))
        blocked = {a for a in actions if rng.random() < 0.08}
        opt = brute_force(actions, window, blocked)
        tag = f"trial {t} shape={shape} n={n} W={window}"

        cp = cp_sat_optimize(actions, window, blocked)
        if opt is None:
            record("CP-SAT detects infeasible", cp.solver_status == "INFEASIBLE", f"{tag} got {cp.solver_status}")
        else:
            record("CP-SAT = brute-force optimum", cp.solver_status == "OPTIMAL" and cp.objective_value == opt,
                   f"{tag} cp={cp.objective_value}/{cp.solver_status} opt={opt}")
            record("CP-SAT plan feasible", feasible(actions, cp.selected_ids, window, blocked), tag)

        dp = dp_optimize(actions, window, blocked)
        if dp.solver_status == "OPTIMAL":
            record(f"DP = brute-force optimum ({shape})", opt is not None and dp.objective_value == opt,
                   f"{tag} dp={dp.objective_value} opt={opt}")
            record("DP plan feasible", feasible(actions, dp.selected_ids, window, blocked), tag)
        elif dp.solver_status == "INFEASIBLE":
            record("DP detects infeasible", opt is None, f"{tag} opt={opt}")
        else:  # NOT_APPLICABLE must only happen on genuine multi-prerequisite instances
            record("DP only declines on general DAGs", shape == "dag", f"{tag} status={dp.solver_status}")

        gr = greedy_optimize(actions, window, blocked)
        if gr.solver_status == "FEASIBLE":
            record("Greedy plan feasible", feasible(actions, gr.selected_ids, window, blocked), tag)
            record("Greedy never claims optimality", not gr.optimality_proven, tag)
            if opt is not None:
                record("Greedy <= optimum", gr.objective_value <= opt, f"{tag} g={gr.objective_value} opt={opt}")
            plain = shape == "none" and not any(a.mandatory for a in actions.values()) and not blocked
            if plain and opt:
                ratio = gr.objective_value / opt
                ratios.append(ratio)
                record("Greedy >= 1/2 optimum (plain knapsack)", ratio >= 0.5, f"{tag} ratio={ratio:.3f}")
        else:
            record("Greedy INFEASIBLE only when truly infeasible", opt is None or any(a.mandatory for a in actions.values()),
                   f"{tag} opt={opt}")
    return ratios


# ─────────────────────────── graph instances ───────────────────────────

def reference_sccs(nodes: list[str], edges: list[tuple[str, str]]) -> set[frozenset[str]]:
    adj = defaultdict(set)
    for a, b in edges:
        adj[a].add(b)

    def reach(s: str) -> set[str]:
        seen, stack = {s}, [s]
        while stack:
            for nxt in adj[stack.pop()]:
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return seen

    r = {v: reach(v) for v in nodes}
    return {frozenset(u for u in nodes if u in r[v] and v in r[u]) for v in nodes}


def graph_suite(trials: int) -> None:
    rng = random.Random(7)
    for t in range(trials):
        n = rng.randint(1, 40)
        nodes = [f"n{i}" for i in range(n)]
        density = rng.choice([0.0, 0.03, 0.08, 0.2])
        acyclic = t % 2 == 0
        edges = sorted({(a, b) for i, a in enumerate(nodes) for j, b in enumerate(nodes)
                        if a != b and rng.random() < density and (not acyclic or j < i)})
        if t % 7 == 3 and n:  # sprinkle self-loops
            v = rng.choice(nodes)
            edges = sorted(set(edges) | {(v, v)})
        g = analyze_graph(tuple(nodes), tuple(edges))
        tag = f"graph {t} V={n} E={len(edges)}"

        ref = reference_sccs(nodes, edges)
        got = {frozenset(c) for c in g.components}
        record("Tarjan SCCs = reference SCCs", got == ref, tag)
        self_loops = {a for a, b in edges if a == b}
        ref_cyclic = {c for c in ref if len(c) > 1 or next(iter(c)) in self_loops}
        record("Cyclic components correct", {frozenset(c) for c in g.cyclic_components} == ref_cyclic, tag)

        cyclic_nodes = set().union(*ref_cyclic) if ref_cyclic else set()
        adj = defaultdict(set)
        for a, b in edges:
            adj[a].add(b)

        def hits_cycle(v: str) -> bool:
            seen, stack = {v}, [v]
            while stack:
                x = stack.pop()
                if x in cyclic_nodes:
                    return True
                for y in adj[x]:
                    if y not in seen:
                        seen.add(y)
                        stack.append(y)
            return False

        record("Blocked nodes = nodes reaching a cycle", set(g.blocked_nodes) == {v for v in nodes if hits_cycle(v)},
               f"{tag} got={sorted(g.blocked_nodes)}")
        order = g.topological_order
        record("Topological order is a permutation", sorted(order) == sorted(nodes), tag)
        pos = {v: i for i, v in enumerate(order)}
        record("Every edge: prerequisite before dependent",
               all(pos[b] < pos[a] for a, b in edges if g.component_of[a] != g.component_of[b]), tag)
        if acyclic and not self_loops:
            record("DAG input -> no cycles reported", not g.cyclic_components, tag)


# ─────────────────────────── scheduler ───────────────────────────

def schedule_suite(trials: int) -> None:
    rng = random.Random(99)
    for t in range(trials):
        actions = make_actions(rng, rng.randint(1, 25), rng.choice(["none", "forest", "dag"]), mandatory=False)
        window = rng.randint(10, 600)
        chosen = cp_sat_optimize(actions, window, set()).selected_ids
        entries, _, _ = schedule_actions(actions, set(chosen), window)
        tag = f"schedule {t}"
        by_id = {e["action_id"]: e for e in entries}
        record("Schedule covers every selected action", set(by_id) == set(chosen), tag)
        ivs = sorted((e["start_minute"], e["finish_minute"]) for e in entries)
        record("Schedule has no overlap", all(ivs[i][1] <= ivs[i + 1][0] for i in range(len(ivs) - 1)), tag)
        record("Schedule fits the window", all(e["finish_minute"] <= window for e in entries), tag)
        record("Prerequisites finish before dependents start",
               all(by_id[p]["finish_minute"] <= e["start_minute"] for e in entries for p in actions[e["action_id"]].prerequisites if p in by_id), tag)
        record("Durations preserved", all(e["finish_minute"] - e["start_minute"] == actions[e["action_id"]].duration_minutes for e in entries), tag)


if __name__ == "__main__":
    ratios = knapsack_suite(int(sys.argv[1]) if len(sys.argv) > 1 else 600)
    graph_suite(400)
    schedule_suite(300)
    width = max(map(len, TALLY))
    total_ok = total = 0
    for name, (ok, n) in TALLY.items():
        total_ok += ok
        total += n
        print(f"{'PASS' if ok == n else 'FAIL'}  {name:<{width}}  {ok}/{n}")
    if ratios:
        print(f"\nGreedy / optimum on {len(ratios)} plain-knapsack instances: "
              f"min {min(ratios):.3f}  mean {sum(ratios) / len(ratios):.3f}  "
              f"optimal in {sum(r == 1 for r in ratios)} ({100 * sum(r == 1 for r in ratios) / len(ratios):.0f}%)")
    print(f"\n{total_ok}/{total} checks passed")
    for f in FAILS:
        print("  ", f)
    sys.exit(0 if total_ok == total else 1)
