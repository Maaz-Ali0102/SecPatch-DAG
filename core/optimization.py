from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from time import perf_counter
from typing import Any

from ortools.sat.python import cp_model

from .models import PatchAction


CP_SAT_TIME_LIMIT_SECONDS = 30.0
SOLVER_STATUSES = {"OPTIMAL", "FEASIBLE", "INFEASIBLE", "UNKNOWN", "MODEL_INVALID", "NOT_APPLICABLE"}
# Dynamic programming is pseudo-polynomial: its tables grow with the window
# size in minutes, not just with the number of actions. These caps keep a
# request fast; larger instances are reported as NOT_APPLICABLE (use CP-SAT).
DP_MAX_TABLE_CELLS = 5_000_000        # 0/1 knapsack: n * (W + 1)
DP_MAX_TREE_OPERATIONS = 20_000_000   # tree knapsack: n * (W + 1)^2


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
    """Greedy by benefit per minute, made a 1/2-approximation.

    Paradigms: greedy + approximation. Step 1 sorts actions by
    benefit/duration and takes each one that still fits. Step 2 compares that
    plan with the single most valuable action that fits on its own and keeps
    the better one.

    Guarantee (plain knapsack: no prerequisites, no mandatory actions): the
    result is at least half the optimum. Proof sketch: let the greedy prefix
    stop at the first action k+1 that does not fit. The fractional-knapsack
    optimum takes the same prefix plus a fraction of action k+1, so
    OPT <= OPT_fractional <= greedy + b_(k+1) <= greedy + best_single, hence
    max(greedy, best_single) >= OPT / 2.
    With prerequisites or mandatory actions it remains a heuristic.

    Complexity: one O(n log n) sort, then a single pass. The plan's total
    minutes and benefit are kept as running sums and membership uses sets, so
    accepting or rejecting an action costs O(1 + c), where c is the number of
    its prerequisites not yet in the plan. Without prerequisites the whole
    algorithm is O(n log n); with h prerequisite links it is O(n log n + n*h)
    in the worst case (a rejected action's chain may be walked again later).
    """
    _validate_optimizer_inputs(actions, window_minutes, blocked_action_ids)
    started = perf_counter()
    selected: set[str] = set()
    used_minutes = 0
    deferred: list[str] = []
    deferred_set: set[str] = set()
    trace: list[dict[str, object]] = []

    def missing(action_id: str, base: set[str]) -> list[str] | None:
        """Actions that must be added to ``base`` to take ``action_id``.

        Returns the prerequisite closure of ``action_id`` minus what ``base``
        already holds, or None if any required action is unknown or blocked.
        Nothing is modified, so a rejected attempt needs no copy of the plan
        (all-or-nothing). Iterative so long chains cannot hit the recursion
        limit.
        """
        if action_id in base:
            return []
        needed: list[str] = []
        seen: set[str] = set()
        work = [action_id]
        while work:
            current = work.pop()
            if current in base or current in seen:
                continue
            if current not in actions or current in blocked_action_ids:
                return None
            seen.add(current)
            needed.append(current)
            work.extend(actions[current].prerequisites)
        return needed

    def minutes(ids: list[str]) -> int:
        return sum(actions[action_id].duration_minutes for action_id in ids)

    def defer(action_id: str) -> None:
        deferred.append(action_id)
        deferred_set.add(action_id)

    for action in actions.values():
        if not action.mandatory:
            continue
        needed = missing(action.id, selected)
        if needed is None:
            defer(action.id)
            trace.append({"algorithm": "greedy", "event": "blocked", "action": action.id, "reason": "cycle_or_prerequisite"})
        elif used_minutes + minutes(needed) <= window_minutes:
            selected.update(needed)
            used_minutes += minutes(needed)
            trace.append({"algorithm": "greedy", "event": "selected", "action": action.id, "reason": "mandatory"})
        else:
            defer(action.id)
            trace.append({"algorithm": "greedy", "event": "blocked", "action": action.id, "reason": "mandatory_window"})

    if any(action.mandatory and action.id not in selected for action in actions.values()):
        return _result("precedence_greedy", "INFEASIBLE", set(), actions, list(actions),
                       (perf_counter() - started) * 1000, trace)
    forced = set(selected)  # mandatory actions and their prerequisites
    forced_minutes = used_minutes
    ordered = sorted(actions.values(), key=lambda action: (-Fraction(action.benefit, action.duration_minutes), -action.priority, action.id))
    for action in ordered:
        if action.id in selected or action.id in deferred_set:
            continue
        if action.id in blocked_action_ids:
            defer(action.id)
            trace.append({"algorithm": "greedy", "event": "blocked", "action": action.id, "reason": "cyclic_scc"})
            continue
        needed = missing(action.id, selected)
        if needed is not None and used_minutes + minutes(needed) <= window_minutes:
            selected.update(needed)
            used_minutes += minutes(needed)
            trace.append({"algorithm": "greedy", "event": "selected", "action": action.id})
        else:
            defer(action.id)
            trace.append({"algorithm": "greedy", "event": "deferred", "action": action.id, "reason": "window_or_prerequisite"})

    # Approximation step: compare with the best single action (plus whatever
    # it requires) that fits; keep whichever plan is worth more.
    def value(ids) -> int:
        return sum(actions[action_id].benefit for action_id in ids)

    forced_value = value(forced)
    selected_value = value(selected)
    best_extra: list[str] | None = None
    best_value = 0
    for action_id in sorted(actions):
        if action_id in forced or action_id in blocked_action_ids:
            continue
        needed = missing(action_id, forced)
        if needed is not None and forced_minutes + minutes(needed) <= window_minutes:
            candidate_value = forced_value + value(needed)
            if best_extra is None or candidate_value > best_value:
                best_extra, best_value = needed, candidate_value
    if best_extra is not None and best_value > selected_value:
        trace.append({"algorithm": "greedy", "event": "approximation_swap",
                      "greedy_value": selected_value, "best_single_value": best_value})
        selected = forced | set(best_extra)
        deferred = [action_id for action_id in actions if action_id not in selected]
    else:
        trace.append({"algorithm": "greedy", "event": "approximation_check", "greedy_value": selected_value,
                      "best_single_value": best_value if best_extra is not None else 0, "kept": "greedy"})
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
    # Bound runtime so a hard instance cannot hang the API. If the limit is
    # reached the honest status is FEASIBLE (or UNKNOWN), never OPTIMAL.
    solver.parameters.max_time_in_seconds = CP_SAT_TIME_LIMIT_SECONDS
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


def dp_optimize(
    actions: dict[str, PatchAction],
    window_minutes: int,
    blocked_action_ids: set[str],
) -> OptimizationResult:
    """Exact selection by dynamic programming (0/1 knapsack).

    Paradigm: dynamic programming. Optimal substructure: the best plan for
    the first i actions with capacity c either skips action i (best plan for
    i-1 actions, capacity c) or takes it (benefit b_i plus the best plan for
    i-1 actions with capacity c - d_i). Overlapping subproblems are stored in
    a table, so each (i, c) pair is solved once.

    * No prerequisites: dp[i][c] = max(dp[i-1][c], dp[i-1][c-d_i] + b_i),
      O(n * W) time. The chosen actions are recovered by backtracking.
    * Prerequisites forming a forest (every action needs at most one other
      action): tree knapsack. An action can only be taken if its parent is
      taken, so each subtree is solved bottom-up and children are merged
      like knapsack items, O(n * W^2) time.
    * General prerequisite graphs (an action with two or more prerequisites)
      make the problem strongly NP-hard, and the pseudo-polynomial tables can
      be too large for big windows: both are reported as NOT_APPLICABLE
      rather than returning a wrong answer.

    Mandatory actions (and their prerequisites) are taken first and reduce
    the capacity. Blocked actions, and everything that depends on them, are
    never selected.
    """
    _validate_optimizer_inputs(actions, window_minutes, blocked_action_ids)
    started = perf_counter()
    trace: list[dict[str, object]] = []
    action_ids = sorted(actions)

    def finish(status: str, selected: set[str]) -> OptimizationResult:
        deferred = [action_id for action_id in action_ids if action_id not in selected]
        trace.append({"algorithm": "dynamic_programming", "event": "solved", "status": status,
                      "objective_value": sum(actions[action_id].benefit for action_id in selected)})
        return _result("dynamic_programming", status, selected, actions, deferred, (perf_counter() - started) * 1000, trace)

    # 1. Actions that can never be selected: blocked, or (transitively)
    #    depending on a blocked or unknown action.
    unavailable: set[str] = set()
    changed = True
    while changed:
        changed = False
        for action_id in action_ids:
            if action_id in unavailable:
                continue
            action = actions[action_id]
            if action_id in blocked_action_ids or any(p not in actions or p in unavailable for p in action.prerequisites):
                unavailable.add(action_id)
                changed = True
    for action_id in sorted(unavailable):
        trace.append({"algorithm": "dynamic_programming", "event": "excluded", "action": action_id,
                      "reason": "blocked_or_depends_on_blocked"})

    # 2. Mandatory actions and their prerequisite closure are forced in.
    forced: set[str] = set()
    work = [action_id for action_id in action_ids if actions[action_id].mandatory]
    while work:
        action_id = work.pop()
        if action_id in forced:
            continue
        if action_id in unavailable:
            trace.append({"algorithm": "dynamic_programming", "event": "infeasible", "reason": "mandatory_action_blocked", "action": action_id})
            return finish("INFEASIBLE", set())
        forced.add(action_id)
        work.extend(actions[action_id].prerequisites)
    capacity = window_minutes - sum(actions[action_id].duration_minutes for action_id in forced)
    if capacity < 0:
        trace.append({"algorithm": "dynamic_programming", "event": "infeasible", "reason": "mandatory_actions_exceed_window"})
        return finish("INFEASIBLE", set())
    for action_id in sorted(forced):
        trace.append({"algorithm": "dynamic_programming", "event": "forced", "action": action_id})

    # 3. Remaining items and their prerequisites still to be satisfied.
    items = [action_id for action_id in action_ids if action_id not in forced and action_id not in unavailable]
    parent: dict[str, str | None] = {}
    for action_id in items:
        open_prerequisites = sorted({p for p in actions[action_id].prerequisites if p not in forced})
        if len(open_prerequisites) > 1:
            trace.append({"algorithm": "dynamic_programming", "event": "not_applicable", "reason": "prerequisites_not_a_tree", "action": action_id})
            return finish("NOT_APPLICABLE", set())
        parent[action_id] = open_prerequisites[0] if open_prerequisites else None

    if all(value is None for value in parent.values()):
        selected = _knapsack_01(items, actions, capacity, trace)
    else:
        selected = _knapsack_tree(items, parent, actions, capacity, trace)
    if selected is None:
        return finish("NOT_APPLICABLE", set())
    return finish("OPTIMAL", forced | selected)


def _knapsack_01(items: list[str], actions: dict[str, PatchAction], capacity: int, trace: list[dict[str, object]]) -> set[str] | None:
    """Bottom-up 0/1 knapsack with a take table for backtracking."""
    n = len(items)
    if n * (capacity + 1) > DP_MAX_TABLE_CELLS:
        trace.append({"algorithm": "dynamic_programming", "event": "not_applicable", "reason": "table_too_large", "cells": n * (capacity + 1)})
        return None
    trace.append({"algorithm": "dynamic_programming", "event": "table_created", "variant": "0/1 knapsack",
                  "rows": n, "columns": capacity + 1, "recurrence": "dp[i][c] = max(dp[i-1][c], dp[i-1][c-d_i] + b_i)"})
    best = [0] * (capacity + 1)              # best[c] = dp[i][c] for the current row i
    take = [bytearray(capacity + 1) for _ in range(n)]
    for i, action_id in enumerate(items):
        duration, benefit = actions[action_id].duration_minutes, actions[action_id].benefit
        for c in range(capacity, duration - 1, -1):   # descending c reuses one row safely
            candidate = best[c - duration] + benefit
            if candidate > best[c]:
                best[c] = candidate
                take[i][c] = 1
    selected: set[str] = set()
    c = capacity
    for i in range(n - 1, -1, -1):          # backtrack from dp[n][W]
        if take[i][c]:
            selected.add(items[i])
            c -= actions[items[i]].duration_minutes
    trace.append({"algorithm": "dynamic_programming", "event": "backtracked", "value": best[capacity], "selected": sorted(selected)})
    return selected


def _knapsack_tree(items: list[str], parent: dict[str, str | None], actions: dict[str, PatchAction], capacity: int, trace: list[dict[str, object]]) -> set[str] | None:
    """Tree knapsack: an action can be taken only if its parent is taken."""
    n = len(items)
    if n * (capacity + 1) ** 2 > DP_MAX_TREE_OPERATIONS:
        trace.append({"algorithm": "dynamic_programming", "event": "not_applicable", "reason": "table_too_large", "operations": n * (capacity + 1) ** 2})
        return None
    trace.append({"algorithm": "dynamic_programming", "event": "table_created", "variant": "tree knapsack",
                  "nodes": n, "columns": capacity + 1,
                  "recurrence": "f[v][c] = b_v + best merge of children within c - d_v"})
    negative = float("-inf")
    children: dict[str | None, list[str]] = {}
    for action_id in items:
        children.setdefault(parent[action_id], []).append(action_id)

    def merge(left: list[float], option: list[float]) -> list[float]:
        merged = [negative] * (capacity + 1)
        for c in range(capacity + 1):
            for s in range(c + 1):
                value = left[c - s] + option[s]
                if value > merged[c]:
                    merged[c] = value
        return merged

    # Post-order without recursion: parents after all of their children.
    order: list[str] = []
    stack = list(children.get(None, []))
    while stack:
        node = stack.pop()
        order.append(node)
        stack.extend(children.get(node, []))
    taken_value: dict[str, list[float]] = {}   # f[v][c]: best for v's subtree with v taken, using <= c
    prefixes: dict[str | None, list[list[float]]] = {}

    def combine(node: str | None) -> list[float]:
        accumulated = [0.0] * (capacity + 1)
        steps = [accumulated]
        for child in children.get(node, []):
            option = [max(0.0, value) for value in taken_value[child]]   # skip child, or take it
            accumulated = merge(accumulated, option)
            steps.append(accumulated)
        prefixes[node] = steps
        return accumulated

    for node in reversed(order):
        duration, benefit = actions[node].duration_minutes, actions[node].benefit
        inner = combine(node)
        taken_value[node] = [negative if c < duration else benefit + inner[c - duration] for c in range(capacity + 1)]
    root = combine(None)

    selected: set[str] = set()
    work: list[tuple[str | None, int]] = [(None, capacity)]
    while work:                                  # backtrack through the merges
        node, budget = work.pop()
        if node is not None:
            selected.add(node)
            budget -= actions[node].duration_minutes
        steps = prefixes[node]
        node_children = children.get(node, [])
        remaining = budget
        for index in range(len(node_children) - 1, -1, -1):
            child = node_children[index]
            before, after = steps[index], steps[index + 1]
            child_value = taken_value[child]
            for s in range(remaining + 1):
                option = max(0.0, child_value[s])
                if before[remaining - s] + option == after[remaining]:
                    if option > 0:  # zero-value subtrees are skipped
                        work.append((child, s))
                        remaining -= s
                    break
    trace.append({"algorithm": "dynamic_programming", "event": "backtracked", "value": int(root[capacity]), "selected": sorted(selected)})
    return selected


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
    key = "cp_sat" if exact.method in {"cp_sat", "greedy"} else exact.method
    return {
        "greedy": {
            "objective_value": greedy.objective_value,
            "runtime_ms": greedy.runtime_ms,
            "solver_status": greedy.solver_status,
            "optimality_proven": greedy.optimality_proven,
            "selected_actions": sorted(greedy.selected_ids),
        },
        key: {
            "objective_value": exact.objective_value,
            "runtime_ms": exact.runtime_ms,
            "solver_status": exact.solver_status,
            "optimality_proven": exact.optimality_proven,
            "selected_actions": sorted(exact.selected_ids),
        },
    }
