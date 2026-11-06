import json
from pathlib import Path

import pytest

from core.engine import run_analysis
from core.graph import analyze_graph
from core.models import Dataset, PatchAction
from core.scheduling import schedule_actions
from core.validation import validate_plan


def dataset(packages=(), dependencies=(), actions=()):
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


def test_simple_dag_uses_prerequisite_first_order() -> None:
    analysis = analyze_graph(("app", "lib", "db"), (("app", "lib"), ("lib", "db")))
    assert analysis.topological_order == ["db", "lib", "app"]


def test_multiple_sccs_and_self_loop_are_detected() -> None:
    analysis = analyze_graph(
        ("a", "b", "c", "d", "e"),
        (("a", "b"), ("b", "a"), ("c", "c"), ("d", "e")),
    )
    assert sorted(analysis.cyclic_components) == [["a", "b"], ["c"]]
    assert analysis.topological_order.index("e") < analysis.topological_order.index("d")


def test_cyclic_and_transitive_cyclic_actions_are_blocked() -> None:
    data = dataset(
        ("cycle-a", "cycle-b", "safe"),
        (("cycle-a", "cycle-b"), ("cycle-b", "cycle-a")),
        (
            PatchAction("blocked", "cycle-a", 5, 50, 50),
            PatchAction("depends-on-blocked", "safe", 5, 100, 100, ("blocked",)),
        ),
    )
    result = run_analysis(data, 20)
    assert result["optimization"]["selected_actions"] == []
    assert result["optimization"]["blocked_actions"] == ["blocked"]
    assert set(result["optimization"]["deferred_actions"]) == {"blocked", "depends-on-blocked"}
    assert result["validation"]["valid"]
    assert any(item["event"] == "deferred" for item in result["trace"])


def test_prerequisite_closure_is_selected() -> None:
    data = dataset(
        ("base", "app"),
        (),
        (
            PatchAction("base-patch", "base", 5, 10, 10),
            PatchAction("app-patch", "app", 5, 100, 100, ("base-patch",)),
        ),
    )
    result = run_analysis(data, 10)
    assert {item["id"] for item in result["optimization"]["selected_actions"]} == {"base-patch", "app-patch"}


def test_mandatory_patch_exceeding_window_is_not_scheduled() -> None:
    data = dataset(("app",), (), (PatchAction("required", "app", 20, 100, 100, mandatory=True),))
    result = run_analysis(data, 5)
    assert result["schedule"]["entries"] == []
    assert result["schedule"]["total_duration_minutes"] == 0
    assert not result["validation"]["valid"]
    assert "Mandatory action required is not selected" in result["validation"]["violations"]
    assert all(entry["finish_minute"] <= 5 for entry in result["schedule"]["entries"])


def test_mandatory_prerequisite_chain_fits() -> None:
    data = dataset(
        ("base", "app"),
        (),
        (
            PatchAction("base-patch", "base", 5, 10, 10),
            PatchAction("app-patch", "app", 5, 100, 100, ("base-patch",), mandatory=True),
        ),
    )
    result = run_analysis(data, 10)
    assert {item["id"] for item in result["optimization"]["selected_actions"]} == {"base-patch", "app-patch"}
    assert result["validation"]["valid"]


def test_zero_window_and_empty_dataset() -> None:
    result = run_analysis(dataset(), 0)
    assert result["statistics"]["package_count"] == 0
    assert result["schedule"]["entries"] == []
    assert result["validation"]["valid"]


def test_isolated_package_is_not_a_cycle() -> None:
    result = run_analysis(dataset(("isolated",)), 0)
    assert result["graph"]["cyclic_components"] == []
    assert result["statistics"]["cycle_count"] == 0


@pytest.mark.parametrize(
    "payload",
    [
        {"packages": [{"id": "a"}, {"id": "a"}]},
        {"packages": [{"id": "a"}], "dependencies": [{"from": "a", "to": "missing"}]},
        {"packages": [{"id": "a"}], "actions": [{"id": "p", "package_id": "a", "duration_minutes": 0, "benefit": 1}]},
        {"packages": [{"id": "a"}], "actions": [{"id": "p", "package_id": "a", "duration_minutes": -1, "benefit": 1}]},
        {"packages": [{"id": "a"}], "actions": [{"id": "p", "package_id": "a", "duration_minutes": 1, "benefit": 1, "prerequisites": ["missing"]}]},
        {"packages": [{"id": "a"}], "actions": [{"id": "p", "package_id": "a", "duration_minutes": 1.5, "benefit": 1}]},
        {"packages": [{"id": "a"}], "actions": [{"id": "p", "package_id": "a", "duration_minutes": 1, "benefit": 1.5}]},
        {"packages": [{"id": "a"}], "actions": [
            {"id": "p", "package_id": "a", "duration_minutes": 1, "benefit": 1, "prerequisites": ["q"]},
            {"id": "q", "package_id": "a", "duration_minutes": 1, "benefit": 1, "prerequisites": ["p"]},
        ]},
    ],
)
def test_strict_dataset_validation(payload) -> None:
    with pytest.raises(ValueError):
        Dataset.from_dict(payload)


def test_independent_validator_catches_invalid_execution_order_and_window() -> None:
    actions = {
        "base": PatchAction("base", "base", 5, 1, 1),
        "app": PatchAction("app", "app", 5, 1, 1, ("base",)),
    }
    violations = validate_plan(
        actions,
        {"base", "app"},
        [
            {"action_id": "app", "package_id": "app", "start_minute": 0, "finish_minute": 5, "duration_minutes": 5},
            {"action_id": "base", "package_id": "base", "start_minute": 5, "finish_minute": 10, "duration_minutes": 5},
        ],
        7,
        set(),
    )
    assert any("appears before a prerequisite" in violation for violation in violations)
    assert any("exceeds the maintenance window" in violation for violation in violations)


def test_independent_validator_catches_selected_action_missing_from_schedule() -> None:
    actions = {"patch": PatchAction("patch", "app", 5, 1, 1)}
    violations = validate_plan(actions, {"patch"}, [], 5, set())
    assert violations == ["Selected actions are missing from schedule: ['patch']"]


def test_scheduler_is_deterministic_and_uses_smith_ratio() -> None:
    actions = {
        "slow": PatchAction("slow", "slow", 10, 1, 10),
        "fast": PatchAction("fast", "fast", 5, 1, 10),
        "tie": PatchAction("tie", "tie", 5, 1, 10),
    }
    first, first_violations, first_trace = schedule_actions(actions, set(actions), 30)
    second, second_violations, _ = schedule_actions(actions, set(actions), 30)
    assert [entry["action_id"] for entry in first] == ["fast", "tie", "slow"]
    assert first == second
    assert first_violations == second_violations == []
    assert first_trace[0]["smith_ratio"] == 2.0


def test_schedule_duration_never_exceeds_window() -> None:
    actions = {"long": PatchAction("long", "long", 10, 1, 1)}
    entries, violations, trace = schedule_actions(actions, {"long"}, 5)
    assert entries == []
    assert violations
    assert trace[0]["event"] == "deferred"


def test_cli_sample_shape() -> None:
    path = Path(__file__).parents[1] / "datasets" / "samples" / "small.json"
    result = run_analysis(Dataset.from_dict(json.loads(path.read_text(encoding="utf-8"))), 120)
    assert result["schema_version"] == "1.0"
    assert isinstance(result["trace"], list)
    assert result["configuration"]["dependency_direction"] == "dependent_to_prerequisite"
