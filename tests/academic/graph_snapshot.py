"""Record or compare analyze_graph / graph_contract output on many random graphs.

  python -I tests/academic/graph_snapshot.py record  out.json
  python -I tests/academic/graph_snapshot.py compare out.json

Every field is compared, including the full Tarjan/Kahn trace, so a change
that only alters how results are computed must match 100%.
"""
from __future__ import annotations

import dataclasses
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.graph import analyze_graph, graph_contract  # noqa: E402


def graphs():
    rng = random.Random(31337)
    for t in range(1500):
        n = rng.randint(0, 45)
        names = [f"{rng.choice('abcxyz')}{i}" for i in range(n)]
        rng.shuffle(names)
        density = rng.choice([0, .02, .05, .1, .25])
        edges = set()
        for a in names:
            for b in names:
                if a != b and rng.random() < density:
                    edges.add((a, b))
        if names and t % 4 == 0:
            for _ in range(rng.randint(1, 3)):
                v = rng.choice(names)
                edges.add((v, v))
        edge_list = sorted(edges)
        rng.shuffle(edge_list)  # input order must not matter for the result
        yield t, tuple(names), tuple(edge_list)


def run():
    out = {}
    for t, nodes, edges in graphs():
        g = analyze_graph(nodes, edges)
        out[str(t)] = [json.loads(json.dumps(dataclasses.asdict(g), default=str)),
                       json.loads(json.dumps(graph_contract(g), default=str))]
    return out


if __name__ == "__main__":
    mode, path = sys.argv[1], Path(sys.argv[2])
    now = run()
    if mode == "record":
        path.write_text(json.dumps(now))
        print(f"recorded {len(now)} graphs")
    else:
        before = json.loads(path.read_text())
        diff = [k for k in before if before[k] != now[k]]
        print(f"{len(before) - len(diff)}/{len(before)} graphs identical (analysis, contract, trace)")
        for k in diff[:3]:
            a, b = before[k][0], now[k][0]
            print("  DIFF graph", k, [f for f in a if a[f] != b[f]], "contract differs:", before[k][1] != now[k][1])
        sys.exit(1 if diff else 0)
