"""Record or compare greedy_optimize's exact output on many random instances.

  python -I tests/academic/greedy_snapshot.py record  out.json
  python -I tests/academic/greedy_snapshot.py compare out.json

"Exact" means selected ids, deferred ids, objective, duration, status and the
full trace, so a refactor that only changes bookkeeping must match 100%.
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.models import PatchAction  # noqa: E402
from core.optimization import greedy_optimize  # noqa: E402


def instances():
    rng = random.Random(4242)
    for t in range(2000):
        n = rng.randint(0, 30)
        ids = [f"a{i:02d}" for i in range(n)]
        shape = t % 4
        acts = {}
        for i, aid in enumerate(ids):
            pre = ()
            if i and shape == 1 and rng.random() < .6:
                pre = (rng.choice(ids[:i]),)
            elif i and shape >= 2 and rng.random() < .6:
                pre = tuple(sorted(rng.sample(ids[:i], rng.randint(1, min(3, i)))))
            if shape == 3 and rng.random() < .05:
                pre = pre + ("missing-action",)
            d = rng.choice([rng.randint(1, 40), 10, 20])  # repeated values force ratio ties
            acts[aid] = PatchAction(aid, f"p{i}", d, rng.choice([rng.randint(0, 100), d, 2 * d]), rng.randint(0, 100), pre,
                                    mandatory=rng.random() < (.1 if t % 5 == 0 else 0))
        window = rng.randint(0, max(1, sum(a.duration_minutes for a in acts.values())))
        blocked = {a for a in ids if rng.random() < .07}
        yield t, acts, window, blocked


def run():
    out = {}
    for t, acts, w, b in instances():
        r = greedy_optimize(acts, w, b)
        out[str(t)] = [r.solver_status, sorted(r.selected_ids), list(r.deferred_ids), r.objective_value,
                       r.total_duration_minutes, json.loads(json.dumps(r.trace, default=str))]
    return out


if __name__ == "__main__":
    mode, path = sys.argv[1], Path(sys.argv[2])
    now = run()
    if mode == "record":
        path.write_text(json.dumps(now))
        print(f"recorded {len(now)} instances")
    else:
        before = json.loads(path.read_text())
        diff = [k for k in before if before[k] != now[k]]
        print(f"{len(before) - len(diff)}/{len(before)} instances identical (status, selection, deferred, value, trace)")
        for k in diff[:5]:
            print("  DIFF", k, "\n   before", before[k][:5], "\n   after ", now[k][:5])
        sys.exit(1 if diff else 0)
