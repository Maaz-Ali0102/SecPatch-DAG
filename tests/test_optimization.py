from itertools import product

from core.engine import run_analysis
from core.models import Dataset, PatchAction
from core.optimization import cp_sat_optimize


def make_dataset(packages, actions, dependencies=()):
    return Dataset.from_dict({
        "packages": [{"id": package} for package in packages],
        "dependencies": [{"from": source, "to": target} for source, target in dependencies],
        "actions": [
            {
                "id": action.id,
                "package_id": action.package_id,
                "duration_minutes": action.duration_minutes,
                "benefit": action.benefit,
                "priority": action.priority,
                "prerequisites": list(action.prerequisites),
                "mandatory": action.mandatory,
            }
            for action in actions
        ],
    })


def brute_force(actions, window):
    best_value = -1
    best_ids = set()
    action_list = list(actions)
    for bits in product((0, 1), repeat=len(action_list)):
        selected = {action.id for action, bit in zip(action_list, bits) if bit}
        if any(action.mandatory and action.id not in selected for action in action_list):
            continue
        if any(not set(action.prerequisites) <= selected for action in action_list if action.id in selected):
            continue
        if sum(action.duration_minutes for action in action_list if action.id in selected) > window:
            continue
        value = sum(action.benefit for action in action_list if action.id in selected)
        if value > best_value:
            best_value, best_ids = value, selected
    return best_value, best_ids


def test_cp_sat_matches_bruteforce_for_small_instance() -> None:
    actions = (
        PatchAction("a", "a", 3, 5, 5),
        PatchAction("b", "b", 4, 8, 8, ("a",)),
        PatchAction("c", "c", 2, 4, 4),
        PatchAction("d", "d", 5, 10, 10),
    )
    result = cp_sat_optimize({action.id: action for action in actions}, 7, set())
    value, ids = brute_force(actions, 7)
    assert result.solver_status == "OPTIMAL"
    assert result.optimality_proven
    assert result.objective_value == value
    assert set(result.selected_ids) == ids


def test_cp_sat_handles_multiple_prerequisites_and_closure() -> None:
    actions = (
        PatchAction("base-a", "a", 2, 3, 3),
        PatchAction("base-b", "b", 2, 3, 3),
        PatchAction("combined", "c", 2, 20, 20, ("base-a", "base-b")),
    )
    result = cp_sat_optimize({action.id: action for action in actions}, 6, set())
    assert result.solver_status == "OPTIMAL"
    assert set(result.selected_ids) == {"base-a", "base-b", "combined"}


def test_cp_sat_mandatory_action_and_chain() -> None:
    actions = (
        PatchAction("base", "base", 2, 1, 1),
        PatchAction("required", "app", 3, 10, 10, ("base",), mandatory=True),
        PatchAction("optional", "other", 2, 5, 5),
    )
    result = cp_sat_optimize({action.id: action for action in actions}, 5, set())
    assert result.solver_status == "OPTIMAL"
    assert set(result.selected_ids) == {"base", "required"}


def test_cp_sat_reports_infeasible_mandatory_requirements() -> None:
    actions = {"required": PatchAction("required", "app", 6, 10, 10, mandatory=True)}
    result = cp_sat_optimize(actions, 5, set())
    assert result.solver_status == "INFEASIBLE"
    assert not result.optimality_proven
    assert result.selected_ids == frozenset()


def test_cp_sat_zero_window_and_empty_input() -> None:
    result = cp_sat_optimize({}, 0, set())
    assert result.solver_status == "OPTIMAL"
    assert result.objective_value == 0
    assert result.selected_ids == frozenset()


def test_direct_optimizer_rejects_zero_duration_action() -> None:
    actions = {"invalid": PatchAction("invalid", "app", 0, 10, 10)}
    try:
        cp_sat_optimize(actions, 10, set())
    except ValueError as error:
        assert "duration must be greater than zero" in str(error)
    else:
        raise AssertionError("zero-duration action was accepted by CP-SAT")


def test_cp_sat_blocks_cyclic_actions_and_transitive_dependents() -> None:
    actions = (
        PatchAction("cyclic", "cycle-a", 1, 100, 100),
        PatchAction("dependent", "safe", 1, 80, 80, ("cyclic",)),
        PatchAction("safe", "safe-2", 1, 10, 10),
    )
    data = make_dataset(("cycle-a", "cycle-b", "safe", "safe-2"), actions, (("cycle-a", "cycle-b"), ("cycle-b", "cycle-a")))
    result = run_analysis(data, 10, method="cp_sat")
    assert result["optimization"]["solver_status"] == "OPTIMAL"
    assert result["optimization"]["selected_actions"] == [{"id": "safe", "package_id": "safe-2", "duration_minutes": 1, "benefit": 10, "priority": 10, "prerequisites": (), "risk": "medium", "mandatory": False}]
    assert set(result["optimization"]["deferred_actions"]) == {"cyclic", "dependent"}
    assert result["validation"]["valid"]


def test_cp_sat_finds_solution_greedy_misses() -> None:
    actions = (
        PatchAction("better-total", "better", 4, 9, 9),
        PatchAction("higher-ratio", "small", 3, 7, 7),
    )
    data = make_dataset(("better", "small"), actions)
    greedy = run_analysis(data, 6, method="precedence_greedy")
    exact = run_analysis(data, 6, method="cp_sat")
    assert greedy["optimization"]["objective_value"] == 7
    assert exact["optimization"]["objective_value"] == 9
    assert exact["optimization"]["optimality_proven"]
    assert exact["optimization"]["solver_status"] == "OPTIMAL"


def test_engine_comparison_report_contains_both_methods() -> None:
    data = make_dataset(("a",), (PatchAction("a-patch", "a", 1, 5, 5),))
    result = run_analysis(data, 1, method="cp_sat")
    comparison = result["optimization"]["comparison"]
    assert comparison["greedy"]["objective_value"] == 5
    assert comparison["cp_sat"]["objective_value"] == 5
    assert "runtime_ms" in comparison["cp_sat"]
    assert comparison["cp_sat"]["solver_status"] == "OPTIMAL"
