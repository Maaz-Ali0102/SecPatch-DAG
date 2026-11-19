"""Reproduce the CEP experiment: python -m core.cep [--input DATASET --windows 18 13]."""
import argparse
from dataclasses import replace
import json
from pathlib import Path
from time import perf_counter

from .maintenance import MaintenancePlanner
from .models import Dataset

EXAMPLE = Path(__file__).resolve().parents[1] / "datasets/cep/worked.json"
CHANGES = (("base", "crypto"), ("crypto", "policy"), ("policy", "directory"))


def experiment(capacities=(18, 13)):
    data = Dataset.from_dict(json.loads(EXAMPLE.read_text()))
    planner = MaintenancePlanner()
    baseline = planner.plan(data, capacities)
    removed = {a.package_id for a in sorted(data.actions, key=lambda a: (-a.priority, a.id))[:2]}
    reduced = replace(data, packages=tuple(p for p in data.packages if p not in removed),
                      dependencies=tuple(e for e in data.dependencies if not removed.intersection(e)),
                      actions=tuple(a for a in data.actions if a.package_id not in removed))
    sensitivity = MaintenancePlanner().plan(reduced, capacities)
    updated = replace(data, dependencies=data.dependencies + CHANGES)
    start = perf_counter()
    incremental = planner.plan(updated, capacities)
    incremental_ms = 1000 * (perf_counter() - start)
    start = perf_counter()
    full = MaintenancePlanner().plan(updated, capacities)
    full_ms = 1000 * (perf_counter() - start)
    if any(full[k] != incremental[k] for k in ("status", "windows", "benefit", "deferred")):
        raise RuntimeError("Incremental result differs from full recomputation")
    return dict(baseline=baseline, removed=sorted(removed), sensitivity=sensitivity,
                added_dependencies=CHANGES, incremental=incremental,
                incremental_ms=round(incremental_ms, 2), full_ms=round(full_ms, 2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--windows", type=int, nargs="+", default=[18, 13])
    args = parser.parse_args()
    if args.input:
        data = Dataset.from_dict(json.loads(args.input.read_text()))
        result = MaintenancePlanner().plan(data, args.windows)
    else:
        result = experiment(args.windows)
    print(json.dumps(result, indent=2))
