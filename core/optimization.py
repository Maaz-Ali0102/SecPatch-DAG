from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Any

from ortools.sat.python import cp_model

from .models import PatchAction


SOLVER_STATUSES = {"OPTIMAL", "FEASIBLE", "INFEASIBLE", "UNKNOWN", "MODEL_INVALID"}


@dataclass(frozen=True)
class OptimizationResult:
    method: str
    solver_status: str
    optimality_proven: bool
    selected_ids: frozenset[str]
    deferred_ids: tuple[str, ...]
    objective_value: int
    total_duration_minutes: int
    runtime_ms: float
    trace: tuple[dict[str, object], ...]


def _result(
    method: str,
    status: str,
    selected_ids: set[str],
    actions: dict[str, PatchAction],
    deferred_ids: list[str],
    runtime_ms: float,
    trace: list[dict[str, object]],
) -> OptimizationResult:
    if status not in SOLVER_STATUSES:
        raise ValueError(f"Unsupported solver status: {status}")
    return OptimizationResult(
        method=method,
        solver_status=status,
        optimality_proven=status == "OPTIMAL",
        selected_ids=frozenset(selected_ids),
        deferred_ids=tuple(sorted(set(deferred_ids) - selected_ids)),
        objective_value=sum(actions[action_id].benefit for action_id in selected_ids),
        total_duration_minutes=sum(actions[action_id].duration_minutes for action_id in selected_ids),
        runtime_ms=runtime_ms,
        trace=tuple(trace),
    )


def greedy_optimize(
    actions: dict[str, PatchAction],
    window_minutes: int,
    blocked_action_ids: set[str],
) -> OptimizationResult:
    """Run the deterministic non-exact benefit-per-duration baseline."""
    _validate_optimizer_inputs(actions, window_minutes, blocked_action_ids)
    started = perf_counter()
    selected: set[str] = set()
    deferred: list[str] = []
    trace: list[dict[str, object]] = []

    def closure(action_id: str, candidate: set[str], visiting: set[str]) -> bool:
        if action_id in candidate:
            return True
        if action_id not in actions or action_id in blocked_action_ids or action_id in visiting:
            return False
        visiting.add(action_id)
        valid = all(closure(prerequisite, candidate, visiting) for prerequisite in actions[action_id].prerequisites)
        visiting.remove(action_id)
        if valid:
            candidate.add(action_id)
        return valid

    for action in actions.values():
        if not action.mandatory:
            continue
        candidate = set(selected)
        if not closure(action.id, candidate, set()):
            deferred.append(action.id)
            trace.append({"algorithm": "greedy", "event": "blocked", "action": action.id, "reason": "cycle_or_prerequisite"})
        elif sum(actions[action_id].duration_minutes for action_id in candidate) <= window_minutes:
            selected = candidate
            trace.append({"algorithm": "greedy", "event": "selected", "action": action.id, "reason": "mandatory"})
        else:
            deferred.append(action.id)
            trace.append({"algorithm": "greedy", "event": "blocked", "action": action.id, "reason": "mandatory_window"})

    ordered = sorted(actions.values(), key=lambda action: (-action.benefit / action.duration_minutes, -action.priority, action.id))
    for action in ordered:
        if action.id in selected or action.id in deferred:
            continue
        if action.id in blocked_action_ids:
            deferred.append(action.id)
            trace.append({"algorithm": "greedy", "event": "blocked", "action": action.id, "reason": "cyclic_scc"})
            continue
        candidate = set(selected)
        if closure(action.id, candidate, set()) and sum(actions[action_id].duration_minutes for action_id in candidate) <= window_minutes:
            selected = candidate
            trace.append({"algorithm": "greedy", "event": "selected", "action": action.id})
        else:
            deferred.append(action.id)
            trace.append({"algorithm": "greedy", "event": "deferred", "action": action.id, "reason": "window_or_prerequisite"})
    return _result("precedence_greedy", "FEASIBLE", selected, actions, deferred, (perf_counter() - started) * 1000, trace)


def cp_sat_optimize(
    actions: dict[str, PatchAction],
    window_minutes: int,
    blocked_action_ids: set[str],
) -> OptimizationResult:
    """Solve precedence-constrained knapsack with integer CP-SAT coefficients.

    Durations and benefits are already integer domain values, so no scaling is
    required. If future inputs contain decimals, normalize them before this
    module and document the scale in the dataset contract.
    """
    _validate_optimizer_inputs(actions, window_minutes, blocked_action_ids)
    started = perf_counter()
    model = cp_model.CpModel()
    action_ids = sorted(actions)
    variables = {action_id: model.NewBoolVar(f"select_{index}") for index, action_id in enumerate(action_ids)}
    trace: list[dict[str, object]] = [{"algorithm": "cp_sat", "event": "model_created", "action_count": len(action_ids)}]
    for action_id in action_ids:
        action = actions[action_id]
        if action_id in blocked_action_ids:
            model.Add(variables[action_id] == 0)
            trace.append({"algorithm": "cp_sat", "event": "blocked", "action": action_id, "reason": "cyclic_scc"})
        if action.mandatory:
            model.Add(variables[action_id] == 1)
            trace.append({"algorithm": "cp_sat", "event": "mandatory_constraint", "action": action_id})
        for prerequisite in action.prerequisites:
            model.Add(variables[action_id] <= variables[prerequisite])
            trace.append({"algorithm": "cp_sat", "event": "prerequisite_constraint", "action": action_id, "prerequisite": prerequisite})
    model.Add(sum(actions[action_id].duration_minutes * variables[action_id] for action_id in action_ids) <= window_minutes)
    model.Maximize(sum(actions[action_id].benefit * variables[action_id] for action_id in action_ids))
    solver = cp_model.CpSolver()
    solver.parameters.num_search_workers = 1
    status_code = solver.Solve(model)
    status_names = {
        cp_model.OPTIMAL: "OPTIMAL",
        cp_model.FEASIBLE: "FEASIBLE",
        cp_model.INFEASIBLE: "INFEASIBLE",
        cp_model.UNKNOWN: "UNKNOWN",
        cp_model.MODEL_INVALID: "MODEL_INVALID",
    }
    status = status_names.get(status_code, "UNKNOWN")
    selected = {
        action_id for action_id in action_ids
        if status in {"OPTIMAL", "FEASIBLE"} and solver.Value(variables[action_id]) == 1
    }
    deferred = [action_id for action_id in action_ids if action_id not in selected]
    trace.append({"algorithm": "cp_sat", "event": "solved", "status": status, "objective_value": sum(actions[action_id].benefit for action_id in selected)})
    return _result("cp_sat", status, selected, actions, deferred, (perf_counter() - started) * 1000, trace)


def _validate_optimizer_inputs(
    actions: dict[str, PatchAction],
    window_minutes: int,
    blocked_action_ids: set[str],
) -> None:
    if isinstance(window_minutes, bool) or not isinstance(window_minutes, int) or window_minutes < 0:
        raise ValueError("window_minutes must be a non-negative integer")
    unknown_blocked = blocked_action_ids - actions.keys()
    if unknown_blocked:
        raise ValueError(f"Blocked action IDs are unknown: {sorted(unknown_blocked)}")
    for action in actions.values():
        if action.duration_minutes <= 0:
            raise ValueError(f"Action {action.id} duration must be greater than zero")
        if action.benefit < 0 or action.priority < 0:
            raise ValueError(f"Action {action.id} benefit and priority must be non-negative")


def comparison_report(greedy: OptimizationResult, exact: OptimizationResult) -> dict[str, Any]:
    return {
        "greedy": {
            "objective_value": greedy.objective_value,
            "runtime_ms": greedy.runtime_ms,
            "solver_status": greedy.solver_status,
            "optimality_proven": greedy.optimality_proven,
            "selected_actions": sorted(greedy.selected_ids),
        },
        "cp_sat": {
            "objective_value": exact.objective_value,
            "runtime_ms": exact.runtime_ms,
            "solver_status": exact.solver_status,
            "optimality_proven": exact.optimality_proven,
            "selected_actions": sorted(exact.selected_ids),
        },
    }
