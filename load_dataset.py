"""Load one diagnostic dataset into SecPatch-DAG through the API, the same way the dashboard does.

Usage (backend must be running):
    python load_dataset.py non_optimized 120
    python load_dataset.py large_inventory 600
    python load_dataset.py invalid

It creates a new project + environment, registers the assets, imports the
inventory and OSV files, runs greedy and CP-SAT, and prints what happened at
each step. Then open the dashboard and select the printed project name.
"""
import json
import sys
import time
from pathlib import Path

import httpx

API = "http://127.0.0.1:8000/api/v1"
DATA = Path(__file__).parent / "diagnostic_datasets" / "datasets"
client = httpx.Client(base_url=API, timeout=120)


def call(method: str, path: str, body: dict | None = None) -> dict | list:
    response = client.request(method, path, json=body)
    if response.status_code >= 400:
        raise RuntimeError(f"{method} {path} -> {response.status_code}: {response.json().get('detail')}")
    return response.json()


def workspace(name: str) -> tuple[str, str]:
    project = call("POST", "/projects", {"name": f"{name} {time.strftime('%H%M%S')}"})
    environment = call("POST", "/environments", {"project_id": project["id"], "name": "prod"})
    print(f"1. Project '{project['name']}' / environment 'prod' created")
    return project["id"], environment["id"]


def load(name: str, window: int) -> None:
    folder = DATA / name
    read = lambda file: json.loads((folder / file).read_text(encoding="utf-8"))
    project_id, environment_id = workspace(name)

    assets = read("asset_registration_manifest.json")["assets"]
    for asset in assets:
        call("POST", "/assets", {"environment_id": environment_id, **asset})
    print(f"2. Registered {len(assets)} assets")

    inventory = read("inventory_offline.json")
    stored = call("POST", "/inventory", {"environment_id": environment_id, "packages": inventory["packages"]})
    print(f"3. Imported {stored['count']} installed packages")

    result = call("POST", "/vulnerabilities/import", {"environment_id": environment_id, "osv": read("osv_offline.json"), "inventory": inventory})
    applicability: dict[str, int] = {}
    for candidate in result["candidate_details"]:
        applicability[candidate["applicability"]] = applicability.get(candidate["applicability"], 0) + 1
    print(f"4. OSV: {result['vulnerabilities']} vulnerability records -> {result['candidates']} candidates {applicability}")
    for issue in result["issues"]:
        print(f"     issue: {issue['code']} - {issue['message']}")

    estimates = read("approved_estimates.json")
    total = sum(item["duration_minutes"] for item in estimates.values())
    print(f"5. {len(estimates)} estimates, {total} minutes of work in total, window = {window} minutes")
    for method in ("precedence_greedy", "dynamic_programming", "cp_sat"):
        plan = call("POST", "/persisted-plans", {"project_id": project_id, "environment_id": environment_id, "window_minutes": window, "method": method, "estimates": estimates})
        opt = plan["optimization"]
        print(f"   {method:19} {opt['solver_status']:9} benefit={opt['objective_value']:<6} "
              f"actions={len(opt['selected_actions']):<4} minutes={opt['total_duration_minutes']:<5} "
              f"proven_optimal={opt['optimality_proven']}  ({opt['runtime_ms']:.1f} ms)")
        ignored = plan.get("estimate_review", {}).get("ignored", {})
        if ignored:
            print(f"     {len(ignored)} estimates ignored, e.g. {next(iter(ignored.items()))}")
    print("Open the dashboard and pick this project in the left sidebar to see the plan.")


def invalid() -> None:
    """Send each invalid file on its own and show how the system rejects it."""
    folder = DATA / "invalid_inputs"
    read = lambda file: json.loads((folder / file).read_text(encoding="utf-8"))
    project_id, environment_id = workspace("invalid_inputs")
    baseline = DATA / "baseline"
    for asset in json.loads((baseline / "asset_registration_manifest.json").read_text())["assets"]:
        call("POST", "/assets", {"environment_id": environment_id, **asset})
    # Register the asset IDs the invalid inventory files use, so each file is
    # rejected (or flagged) for the problem it is meant to test.
    for extra in sorted({row.get("asset_id") for file in folder.glob("inventory_*.json") for row in read(file.name)["packages"] if isinstance(row.get("asset_id"), str)}):
        call("POST", "/assets", {"environment_id": environment_id, "name": extra, "external_identifier": extra})
    base_inventory = json.loads((baseline / "inventory_offline.json").read_text())
    call("POST", "/inventory", {"environment_id": environment_id, "packages": base_inventory["packages"]})
    base_osv = json.loads((baseline / "osv_offline.json").read_text())
    call("POST", "/vulnerabilities/import", {"environment_id": environment_id, "osv": base_osv, "inventory": base_inventory})
    print("2. Baseline data loaded as a valid starting point\n")

    for file in sorted(folder.glob("*.json")):
        if file.name == "dataset_manifest.json":
            continue
        payload = read(file.name)
        try:
            if file.name.startswith("inventory"):
                result = call("POST", "/vulnerabilities/import", {"environment_id": environment_id, "osv": base_osv, "inventory": payload})
                states = [f"{c['candidate_key']}={c['applicability']}" for c in result["candidate_details"] if c["candidate_key"].split(":")[0] in {row.get("asset_id") for row in payload["packages"]}]
                outcome = "accepted; issues: " + (", ".join(sorted({issue["code"] for issue in result["issues"]} - {"incomplete_dependency_metadata", "package_not_in_inventory"})) or "none") + (f"; candidates {states}" if states else "")
            elif file.name.startswith("osv"):
                result = call("POST", "/vulnerabilities/import", {"environment_id": environment_id, "osv": payload, "inventory": base_inventory})
                states = [f"{c['candidate_key']}={c['applicability']}" for c in result["candidate_details"] if "BAD" in (c["vulnerability_id"] or "")]
                outcome = f"accepted; candidates {states}; issues: " + ", ".join(sorted({issue['code'] for issue in result['issues']}))
            else:
                estimate = next(iter(payload.values()))
                call("POST", "/persisted-plans", {"project_id": project_id, "environment_id": environment_id, "window_minutes": 60, "method": "cp_sat", "estimates": {"asset-api-prod:OSV-TEST-BASE-0001": estimate}})
                outcome = "ACCEPTED (this would be a bug)"
        except RuntimeError as error:
            outcome = f"rejected -> {error}"
        print(f"{file.name:45} {outcome}")


if __name__ == "__main__":
    try:
        client.get("/health")
    except httpx.ConnectError:
        sys.exit("Backend is not running. Start it first: uvicorn backend.main:app --reload")
    if len(sys.argv) >= 2 and sys.argv[1] == "invalid":
        invalid()
    elif len(sys.argv) == 3:
        load(sys.argv[1], int(sys.argv[2]))
    else:
        print(__doc__)
