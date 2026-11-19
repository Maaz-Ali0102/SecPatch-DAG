"""Correctness tests for the dynamic-programming optimizer (core.optimization.dp_optimize)."""
from __future__ import annotations

import random

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from core.engine import run_analysis
from core.models import Dataset, PatchAction
from core.optimization import DP_MAX_TABLE_CELLS, cp_sat_optimize, dp_optimize, greedy_optimize


def action(action_id: str, duration: int, benefit: int, prerequisites: tuple[str, ...] = (), mandatory: bool = False) -> PatchAction:
    return PatchAction(action_id, "pkg", duration, benefit, benefit, prerequisites, mandatory=mandatory)


def brute_force(actions: dict[str, PatchAction], window: int, blocked: set[str]) -> int | None:
    """Try every subset (2^n) and return the best feasible benefit."""
    ids = sorted(actions)
    best = None
    for mask in range(1 << len(ids)):
        chosen = {ids[i] for i in range(len(ids)) if mask >> i & 1}
        if chosen & blocked:
            continue
        if any(actions[a].mandatory and a not in chosen for a in ids):
            continue
        if any(p not in chosen for a in chosen for p in actions[a].prerequisites):
            continue
        if sum(actions[a].duration_minutes for a in chosen) > window:
            continue
        value = sum(actions[a].benefit for a in chosen)
        best = value if best is None else max(best, value)
    return best


def test_textbook_knapsack_where_greedy_fails() -> None:
    # Baseline dataset numbers: ratios 3.09 > 2.79 > 2.61, window 60.
    actions = {"a": action("a", 22, 68), "b": action("b", 29, 81), "c": action("c", 36, 94)}
    greedy = greedy_optimize(actions, 60, set())
    dp = dp_optimize(actions, 60, set())
    assert (greedy.objective_value, sorted(greedy.selected_ids)) == (149, ["a", "b"])
    assert (dp.objective_value, sorted(dp.selected_ids), dp.solver_status) == (162, ["a", "c"], "OPTIMAL")
    assert dp.optimality_proven


@pytest.mark.parametrize("shape", ["independent", "tree"])
def test_dp_matches_brute_force_and_cp_sat_on_random_instances(shape: str) -> None:
    rng = random.Random(2026)
    for _ in range(250):
        n = rng.randint(1, 9)
        ids = [f"a{i}" for i in range(n)]
        actions = {}
        for i, action_id in enumerate(ids):
            prerequisites = (ids[rng.randrange(i)],) if shape == "tree" and i and rng.random() < 0.6 else ()
            actions[action_id] = action(action_id, rng.randint(1, 12), rng.randint(0, 20), prerequisites, mandatory=rng.random() < 0.08)
        window = rng.randint(0, 45)
        blocked = {a for a in ids if rng.random() < 0.1}
        expected = brute_force(actions, window, blocked)
        result = dp_optimize(actions, window, blocked)
        if expected is None:
            assert result.solver_status == "INFEASIBLE"
            continue
        chosen = set(result.selected_ids)
        assert result.solver_status == "OPTIMAL"
        assert result.objective_value == expected == cp_sat_optimize(actions, window, blocked).objective_value
        assert sum(actions[a].duration_minutes for a in chosen) <= window
        assert not chosen & blocked
        assert all(p in chosen for a in chosen for p in actions[a].prerequisites)


def test_prerequisite_tree_is_respected() -> None:
    # c is worth a lot but needs b, which needs a.
    actions = {"a": action("a", 10, 1), "b": action("b", 10, 1, ("a",)), "c": action("c", 10, 100, ("b",)), "d": action("d", 25, 50)}
    result = dp_optimize(actions, 30, set())
    assert sorted(result.selected_ids) == ["a", "b", "c"] and result.objective_value == 102


def test_general_prerequisite_graph_is_not_applicable() -> None:
    actions = {"a": action("a", 5, 5), "b": action("b", 5, 5), "c": action("c", 5, 50, ("a", "b"))}
    result = dp_optimize(actions, 20, set())
    assert result.solver_status == "NOT_APPLICABLE" and not result.selected_ids
    assert any(event.get("reason") == "prerequisites_not_a_tree" for event in result.trace)


def test_huge_window_is_not_applicable_instead_of_slow() -> None:
    actions = {f"a{i}": action(f"a{i}", 1, 1) for i in range(10)}
    result = dp_optimize(actions, DP_MAX_TABLE_CELLS, set())
    assert result.solver_status == "NOT_APPLICABLE"


def test_mandatory_and_blocked_rules() -> None:
    actions = {"m": action("m", 50, 1, mandatory=True), "x": action("x", 20, 99)}
    assert dp_optimize(actions, 40, set()).solver_status == "INFEASIBLE"
    assert dp_optimize(actions, 70, set()).objective_value == 100
    assert dp_optimize(actions, 70, {"m"}).solver_status == "INFEASIBLE"
    child = {"p": action("p", 5, 5), "q": action("q", 5, 50, ("p",))}
    assert dp_optimize(child, 20, {"p"}).selected_ids == frozenset()


def test_engine_and_api_accept_dynamic_programming() -> None:
    dataset = Dataset.from_dict({"packages": ["pkg"], "actions": [
        {"id": "a", "package_id": "pkg", "duration_minutes": 22, "benefit": 68},
        {"id": "b", "package_id": "pkg", "duration_minutes": 29, "benefit": 81},
        {"id": "c", "package_id": "pkg", "duration_minutes": 36, "benefit": 94},
    ]})
    result = run_analysis(dataset, 60, "dynamic_programming")
    assert result["optimization"]["method"] == "dynamic_programming"
    assert result["optimization"]["objective_value"] == 162 and result["validation"]["valid"]
    response = TestClient(app).post("/api/v1/plans", json={"dataset": {"packages": ["pkg"], "actions": [
        {"id": "a", "package_id": "pkg", "duration_minutes": 22, "benefit": 68},
        {"id": "c", "package_id": "pkg", "duration_minutes": 36, "benefit": 94},
    ]}, "window_minutes": 60, "method": "dynamic_programming"})
    assert response.status_code == 200 and response.json()["optimization"]["objective_value"] == 162


# --- Greedy as a 1/2-approximation ---------------------------------------------

def test_plain_ratio_greedy_failure_is_fixed_by_best_single_item() -> None:
    # Ratio greedy alone takes A (ratio 2) and then B no longer fits: 2 vs 100.
    actions = {"A": action("A", 1, 2), "B": action("B", 100, 100)}
    result = greedy_optimize(actions, 100, set())
    assert sorted(result.selected_ids) == ["B"] and result.objective_value == 100
    assert any(event["event"] == "approximation_swap" for event in result.trace)


def test_greedy_is_always_at_least_half_the_optimum_without_prerequisites() -> None:
    rng = random.Random(12)
    for _ in range(600):
        n = rng.randint(1, 10)
        actions = {f"a{i}": action(f"a{i}", rng.randint(1, 30), rng.randint(0, 40)) for i in range(n)}
        window = rng.randint(0, 80)
        optimum = brute_force(actions, window, set())
        greedy = greedy_optimize(actions, window, set())
        assert 2 * greedy.objective_value >= optimum
        assert greedy.objective_value <= optimum
        assert sum(actions[a].duration_minutes for a in greedy.selected_ids) <= window
