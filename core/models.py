from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PatchAction:
    id: str
    package_id: str
    duration_minutes: int
    benefit: int
    priority: int
    prerequisites: tuple[str, ...] = ()
    risk: str = "medium"
    mandatory: bool = False


@dataclass(frozen=True)
class Dataset:
    packages: tuple[str, ...]
    dependencies: tuple[tuple[str, str], ...]
    actions: tuple[PatchAction, ...]
    atomic_components: tuple[tuple[str, ...], ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Dataset:
        if not isinstance(data, dict):
            raise ValueError("Dataset must be an object")
        packages_data = data.get("packages", [])
        dependencies_data = data.get("dependencies", [])
        actions_data = data.get("actions", [])
        if not isinstance(packages_data, list) or not isinstance(dependencies_data, list) or not isinstance(actions_data, list):
            raise ValueError("packages, dependencies, and actions must be arrays")
        packages_list: list[str] = []
        for item in packages_data:
            package_id = item.get("id") if isinstance(item, dict) else item
            if not isinstance(package_id, str) or not package_id.strip():
                raise ValueError("Every package must have a non-empty string id")
            packages_list.append(package_id)
        if len(packages_list) != len(set(packages_list)):
            raise ValueError("Package IDs must be unique")
        packages = tuple(packages_list)
        dependencies_list: list[tuple[str, str]] = []
        for item in dependencies_data:
            if not isinstance(item, dict) or not isinstance(item.get("from"), str) or not isinstance(item.get("to"), str):
                raise ValueError("Every dependency must contain string from and to values")
            edge = (item["from"], item["to"])
            if edge in dependencies_list:
                raise ValueError(f"Duplicate dependency: {edge[0]}->{edge[1]}")
            dependencies_list.append(edge)
        dependencies = tuple(dependencies_list)
        actions_list: list[PatchAction] = []
        for item in actions_data:
            if not isinstance(item, dict):
                raise ValueError("Every action must be an object")
            required = ("id", "package_id", "duration_minutes", "benefit")
            if any(key not in item for key in required):
                raise ValueError(f"Action is missing one of: {', '.join(required)}")
            try:
                duration = _strict_int(item["duration_minutes"], "duration_minutes")
                benefit = _strict_int(item["benefit"], "benefit")
                priority = _strict_int(item.get("priority", benefit), "priority")
            except ValueError as error:
                raise ValueError(f"Action {item.get('id', '<unknown>')} has invalid numeric fields") from error
            prerequisites = item.get("prerequisites", [])
            if not isinstance(prerequisites, list) or any(not isinstance(value, str) for value in prerequisites):
                raise ValueError(f"Action {item['id']} prerequisites must be an array of strings")
            actions_list.append(PatchAction(
                id=item["id"],
                package_id=item["package_id"],
                duration_minutes=duration,
                benefit=benefit,
                priority=priority,
                prerequisites=tuple(prerequisites),
                risk=str(item.get("risk", "medium")),
                mandatory=bool(item.get("mandatory", False)),
            ))
        actions = tuple(actions_list)
        action_ids = {action.id for action in actions}
        if len(action_ids) != len(actions):
            raise ValueError("Action IDs must be unique")
        package_ids = set(packages)
        for source, target in dependencies:
            if source not in package_ids or target not in package_ids:
                raise ValueError(f"Dependency references unknown package: {source}->{target}")
        for action in actions:
            if not action.id.strip() or action.package_id not in package_ids:
                raise ValueError(f"Action {action.id!r} references an unknown or empty package")
            if action.duration_minutes <= 0:
                raise ValueError(f"Action {action.id} duration must be greater than zero")
            if action.benefit < 0 or action.priority < 0:
                raise ValueError(f"Action {action.id} benefit and priority must be non-negative")
            if len(action.prerequisites) != len(set(action.prerequisites)):
                raise ValueError(f"Action {action.id} has duplicate prerequisites")
            if action.id in action.prerequisites or any(value not in action_ids for value in action.prerequisites):
                raise ValueError(f"Action {action.id} has an invalid prerequisite reference")
        _validate_action_acyclic(actions)
        atomic = tuple(tuple(str(value) for value in component) for component in data.get("atomic_components", []))
        return cls(packages, dependencies, actions, atomic)


def _strict_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer; fractional values are not silently rounded")
    return value


def _validate_action_acyclic(actions: tuple[PatchAction, ...]) -> None:
    action_map = {action.id: action for action in actions}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(action_id: str) -> None:
        if action_id in visiting:
            raise ValueError("Patch action prerequisites contain a cycle")
        if action_id in visited:
            return
        visiting.add(action_id)
        for prerequisite in action_map[action_id].prerequisites:
            visit(prerequisite)
        visiting.remove(action_id)
        visited.add(action_id)

    for action in actions:
        visit(action.id)
