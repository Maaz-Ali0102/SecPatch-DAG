from __future__ import annotations

from typing import Any

from .models import PatchAction


def validate_plan(
    actions: dict[str, PatchAction],
    selected_ids: set[str],
    schedule: list[dict[str, Any]],
    window_minutes: int,
    blocked_packages: set[str],
) -> list[str]:
    violations: list[str] = []
    unknown = selected_ids - actions.keys()
    if unknown:
        violations.append(f"Selected unknown actions: {sorted(unknown)}")
    for action_id in sorted(selected_ids & actions.keys()):
        action = actions[action_id]
        missing = set(action.prerequisites) - selected_ids
        if missing:
            violations.append(f"Action {action_id} is missing prerequisites: {sorted(missing)}")
        if action.package_id in blocked_packages:
            violations.append(f"Action {action_id} belongs to a blocked package")
    if len({entry.get("action_id") for entry in schedule}) != len(schedule):
        violations.append("Schedule contains duplicate action IDs")
    seen: set[str] = set()
    previous_finish = 0
    for entry in schedule:
        action_id = entry.get("action_id")
        if action_id not in selected_ids or action_id not in actions:
            violations.append(f"Schedule contains an unselected or unknown action: {action_id}")
            continue
        start = entry.get("start_minute")
        finish = entry.get("finish_minute")
        duration = entry.get("duration_minutes")
        if not all(isinstance(value, int) for value in (start, finish, duration)):
            violations.append(f"Schedule entry {action_id} has invalid time values")
            continue
        if start < 0 or finish <= start or finish - start != duration or start < previous_finish:
            violations.append(f"Schedule entry {action_id} has invalid interval")
        if finish > window_minutes:
            violations.append(f"Schedule entry {action_id} exceeds the maintenance window")
        if any(prerequisite not in seen for prerequisite in actions[action_id].prerequisites):
            violations.append(f"Schedule entry {action_id} appears before a prerequisite")
        seen.add(action_id)
        previous_finish = max(previous_finish, finish)
    missing_schedule_entries = selected_ids - seen
    if missing_schedule_entries:
        violations.append(f"Selected actions are missing from schedule: {sorted(missing_schedule_entries)}")
    for action in actions.values():
        if action.mandatory and action.id not in selected_ids:
            violations.append(f"Mandatory action {action.id} is not selected")
    return sorted(set(violations))
