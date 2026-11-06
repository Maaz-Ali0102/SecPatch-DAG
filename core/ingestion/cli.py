from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..engine import run_analysis
from .osv import approve_candidates, ingest_osv


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest offline OSV data and run SecPatch-DAG")
    parser.add_argument("--osv", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--estimates", required=True, type=Path)
    parser.add_argument("--window", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = ingest_osv(json.loads(args.osv.read_text(encoding="utf-8")), json.loads(args.inventory.read_text(encoding="utf-8")))
    approved = approve_candidates(result, json.loads(args.estimates.read_text(encoding="utf-8")))
    if approved.approved_dataset is None:
        raise SystemExit("No valid approved planning input was produced")
    analysis = run_analysis(approved.approved_dataset, args.window, "cp_sat")
    output = {
        "ingestion": {
            "vulnerabilities": [record.__dict__ for record in approved.vulnerabilities],
            "inventory": [item.__dict__ for item in approved.inventory],
            "candidates": [candidate.__dict__ for candidate in approved.candidates],
            "issues": approved.issue_dicts(),
        },
        "analysis": analysis,
    }
    args.output.write_text(json.dumps(output, indent=2, default=lambda value: value.__dict__) + "\n", encoding="utf-8")
    print(f"Status: {analysis['status']}")
    print(f"Candidates: {len(approved.candidates)}")
    print(f"Issues: {len(approved.issues)}")
    print(f"Solver: {analysis['optimization']['solver_status']}")
    print(f"Validation: {analysis['validation']['valid']}")


if __name__ == "__main__":
    main()
