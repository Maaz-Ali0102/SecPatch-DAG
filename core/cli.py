from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import run_analysis
from .models import Dataset


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SecPatch-DAG headless analysis")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--window", required=True, type=int)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--method", choices=("precedence_greedy", "cp_sat"), default="precedence_greedy")
    args = parser.parse_args()
    dataset = Dataset.from_dict(json.loads(args.input.read_text(encoding="utf-8")))
    result = run_analysis(dataset, args.window, args.method)
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(f"Status: {result['status']}")
    print(f"Packages: {result['statistics']['package_count']}")
    print(f"Cycles: {result['statistics']['cycle_count']}")
    print(f"Selected actions: {len(result['optimization']['selected_actions'])}")
    print(f"Duration: {result['schedule']['total_duration_minutes']} minutes")
    print(rendered)


if __name__ == "__main__":
    main()
