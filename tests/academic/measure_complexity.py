"""Empirical running-time growth of each algorithm, fitted on a log-log scale.

For each algorithm the input size is doubled repeatedly and the median of
several runs is timed. The slope of log(time) against log(size) estimates the
exponent k in time ~ size^k, which is compared with the stated complexity.

Run:  python -I tests/academic/measure_complexity.py
"""
from __future__ import annotations

import math
import random
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.graph import analyze_graph  # noqa: E402
from core.models import PatchAction  # noqa: E402
from core.optimization import cp_sat_optimize, dp_optimize, greedy_optimize  # noqa: E402
from core.scheduling import schedule_actions  # noqa: E402


def timed(fn, repeats: int = 3) -> float:
    samples = []
    for _ in range(repeats):
        t = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t) * 1000)
    return statistics.median(samples)


def slope(xs: list[float], ys: list[float]) -> float:
    lx, ly = [math.log(x) for x in xs], [math.log(y) for y in ys]
    mx, my = sum(lx) / len(lx), sum(ly) / len(ly)
    return sum((a - mx) * (b - my) for a, b in zip(lx, ly)) / sum((a - mx) ** 2 for a in lx)


def actions(n: int, rng: random.Random, tree: bool = False) -> dict[str, PatchAction]:
    ids = [f"a{i}" for i in range(n)]
    out = {}
    for i, aid in enumerate(ids):
        pre = (ids[rng.randrange(i)],) if tree and i and rng.random() < 0.7 else ()
        out[aid] = PatchAction(aid, f"p{i}", rng.randint(1, 30), rng.randint(1, 100), rng.randint(1, 100), pre)
    return out


def experiment(title: str, claim: str, sizes: list[int], build, run, label: str = "n", repeats: int = 3) -> None:
    times = []
    print(f"\n{title}\n  stated: {claim}")
    for size in sizes:
        data = build(size)
        ms = timed(lambda: run(data), repeats)
        times.append(max(ms, 1e-3))
        print(f"  {label}={size:>8,}  {ms:10.2f} ms")
    print(f"  measured exponent: time ~ {label}^{slope(sizes, times):.2f}")


rng = random.Random(1)

experiment("Greedy (ratio sort + best single), no prerequisites",
           "O(n log n): one sort, then one pass with running totals",
           [250, 500, 1000, 2000, 4000], lambda n: actions(n, rng),
           lambda a: greedy_optimize(a, sum(x.duration_minutes for x in a.values()) // 3, set()))

experiment("DP 0/1 knapsack, window fixed W=1000, n varies",
           "O(n*W) -> linear in n", [100, 200, 400, 800, 1600], lambda n: actions(n, rng),
           lambda a: dp_optimize(a, 1000, set()))

fixed = actions(200, random.Random(2))
experiment("DP 0/1 knapsack, n fixed=200, window W varies",
           "O(n*W) -> linear in W (pseudo-polynomial)", [250, 500, 1000, 2000, 4000], lambda w: w,
           lambda w: dp_optimize(fixed, w, set()), label="W")

forest = actions(60, random.Random(3), tree=True)
experiment("DP tree knapsack (forest prerequisites), n fixed=60, W varies",
           "O(n*W^2) -> quadratic in W", [50, 100, 200, 400, 800], lambda w: w,
           lambda w: dp_optimize(forest, w, set()), label="W")


def graph(v: int):
    r = random.Random(v)
    nodes = tuple(f"v{i}" for i in range(v))
    edges = {(nodes[i], nodes[r.randrange(v)]) for i in range(v) for _ in range(2)}
    return nodes, tuple(sorted(e for e in edges if e[0] != e[1]))


experiment("Tarjan SCC + Kahn topological sort (E ~ 2V, with cycles)",
           "O(V+E) -> linear", [2000, 4000, 8000, 16000, 32000], graph,
           lambda g: analyze_graph(*g), label="V")

experiment("CP-SAT exact solver, W = 1/3 of total work",
           "exponential worst case; time-limited in practice", [50, 100, 200, 400, 800],
           lambda n: actions(n, rng), lambda a: cp_sat_optimize(a, sum(x.duration_minutes for x in a.values()) // 3, set()),
           repeats=1)

experiment("Smith-ratio scheduler over selected jobs (forest prerequisites)",
           "O(s(s+r) + s^2 log s)", [100, 200, 400, 800, 1600], lambda n: actions(n, rng, tree=True),
           lambda a: schedule_actions(a, set(a), 10**9))

# ─── Tightness of the greedy 1/2 bound ───
print("\nGreedy 1/2-approximation: constructed worst case (W = 2k)")
print("  items: A (1 min, 2 pts), B (k min, k pts), C (k min, k pts); optimum = B + C = 2k")
for k in [5, 50, 500, 5000]:
    inst = {"A": PatchAction("A", "pa", 1, 2, 2), "B": PatchAction("B", "pb", k, k, k), "C": PatchAction("C", "pc", k, k, k)}
    g = greedy_optimize(inst, 2 * k, set()).objective_value
    o = cp_sat_optimize(inst, 2 * k, set()).objective_value
    print(f"  k={k:>5}: greedy={g:>6}  optimum={o:>6}  ratio={g / o:.4f}")
