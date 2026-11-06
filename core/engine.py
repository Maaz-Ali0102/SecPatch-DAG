from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from .graph import analyze_graph, graph_contract
from .models import Dataset
from .optimization import comparison_report, cp_sat_optimize, greedy_optimize
from .scheduling import schedule_actions
from .validation import validate_plan


def run_analysis(dataset: Dataset, window_minutes: int, method: str = "precedence_greedy") -> dict[str, Any]:
    if window_minutes < 0:
        raise ValueError("window_minutes must be non-negative")
    if method not in {"precedence_greedy", "cp_sat"}:
        raise ValueError("method must be 'precedence_greedy' or 'cp_sat'")
    graph = analyze_graph(dataset.packages, dataset.dependencies)
    actions = {action.id: action for action in dataset.actions}
    blocked_packages = set(graph.blocked_nodes)
    blocked_action_ids = {action.id for action in dataset.actions if action.package_id in blocked_packages}
    greedy = greedy_optimize(actions, window_minutes, blocked_action_ids)
    chosen = greedy if method == "precedence_greedy" else cp_sat_optimize(actions, window_minutes, blocked_action_ids)
    schedule, schedule_violations, schedule_trace = schedule_actions(actions, set(chosen.selected_ids), window_minutes, blocked_packages)
    violations = validate_plan(actions, set(chosen.selected_ids), schedule, window_minutes, blocked_packages)
    violations = sorted(set(violations + schedule_violations))
    input_fingerprint = hashlib.sha256(json.dumps({
        "packages": dataset.packages,
        "dependencies": dataset.dependencies,
        "actions": [action.__dict__ for action in dataset.actions],
    }, sort_keys=True, default=list).encode()).hexdigest()
    trace = list(graph.trace) + list(chosen.trace) + schedule_trace
    return {
        "schema_version": "1.0",
        "run_id": str(uuid.uuid4()),
        "status": "completed",
        "input_fingerprint": input_fingerprint,
        "configuration": {"window_minutes": window_minutes, "dependency_direction": "dependent_to_prerequisite"},
        "graph": {
            "nodes": graph.nodes,
            "edges": graph.edges,
            "strongly_connected_components": graph.components,
            "cyclic_components": graph.cyclic_components,
            "condensation_edges": graph.condensation_edges,
            "topological_order": graph.topological_order,
            "dependency_analysis": graph_contract(graph),
        },
        "optimization": {
            "status": chosen.solver_status,
            "method": chosen.method,
            "solver_status": chosen.solver_status,
            "objective_value": chosen.objective_value,
            "optimality_proven": chosen.optimality_proven,
            "selected_actions": [actions[action_id].__dict__ for action_id in sorted(chosen.selected_ids)],
            "deferred_actions": list(chosen.deferred_ids),
            "blocked_actions": sorted(blocked_action_ids),
            "total_duration_minutes": chosen.total_duration_minutes,
            "runtime_ms": chosen.runtime_ms,
            "comparison": comparison_report(greedy, chosen),
        },
        "schedule": {"total_duration_minutes": sum(entry["duration_minutes"] for entry in schedule), "entries": schedule},
        "validation": {
            "valid": not violations,
            "violations": violations,
            "warnings": [
                "Greedy selection is a baseline heuristic.",
                "Smith-ratio scheduling is a heuristic and is not globally optimal with precedence constraints.",
            ],
        },
        "trace": trace,
        "statistics": {"package_count": len(dataset.packages), "action_count": len(dataset.actions), "cycle_count": len(graph.cyclic_components)},
    }
