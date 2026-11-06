from __future__ import annotations

from typing import Any

from .models import PatchAction


def schedule_actions(
    actions: dict[str, PatchAction],
    selected_ids: set[str],
    window_minutes: int,
    blocked_packages: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, object]]]:
    """Schedule selected actions using a ready set and Smith's ratio heuristic.

    Among currently ready actions, descending ``priority / duration`` is
    Smith's ratio. With precedence constraints this is a deterministic
    heuristic, not a proof of globally optimal scheduling.
    """
    blocked_packages = blocked_packages or set()
    entries: list[dict[str, Any]] = []
    violations: list[str] = []
    trace: list[dict[str, object]] = []
    remaining = set(selected_ids)
    selected_ids = set(selected_ids)
    elapsed = 0
    while remaining:
        ready = [
            actions[action_id] for action_id in remaining
            if action_id in actions
            and all(prerequisite in selected_ids and prerequisite not in remaining for prerequisite in actions[action_id].prerequisites)
        ]
        ready.sort(key=lambda action: (-action.priority / action.duration_minutes, action.id))
        if not ready:
            violations.append("Selected actions contain an unresolved prerequisite cycle or missing action")
            trace.append({"algorithm": "scheduler", "event": "blocked", "actions": sorted(remaining)})
            break
        action = ready[0]
        if action.package_id in blocked_packages:
            violations.append(f"Action {action.id} belongs to a blocked package")
            trace.append({"algorithm": "scheduler", "event": "blocked", "action": action.id, "reason": "blocked_cycle"})
            remaining.remove(action.id)
            continue
        finish = elapsed + action.duration_minutes
        if finish > window_minutes:
            violations.append(f"Action {action.id} does not fit within the maintenance window")
            trace.append({"algorithm": "scheduler", "event": "deferred", "action": action.id, "reason": "window"})
            remaining.remove(action.id)
            continue
        entry = {
            "action_id": action.id,
            "package_id": action.package_id,
            "start_minute": elapsed,
            "finish_minute": finish,
            "duration_minutes": action.duration_minutes,
        }
        entries.append(entry)
        trace.append({
            "algorithm": "scheduler",
            "event": "scheduled",
            "action": action.id,
            "smith_ratio": action.priority / action.duration_minutes,
            "start_minute": elapsed,
            "finish_minute": finish,
        })
        elapsed = finish
        remaining.remove(action.id)
    return entries, violations, trace
