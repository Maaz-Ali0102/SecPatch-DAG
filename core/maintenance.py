"""Exact multiple-window planning for small, dependency-connected patch groups."""
from dataclasses import dataclass, replace
from itertools import product
from math import prod

from .graph import analyze_graph
from .scheduling import ordered_actions, schedule_actions


class PlanningLimit(ValueError):
    """The requested exact search exceeds the demonstration budget."""


@dataclass(frozen=True)
class Choice:
    benefit: int
    jobs: tuple = ()
    children: tuple = ()


def recover(choice):
    if choice.children:
        for child in choice.children:
            yield from recover(child)
    else:
        yield from choice.jobs


def split_groups(dataset):
    """Undirected independence groups include package edges and hard action requirements."""
    adjacency = {node: set() for node in dataset.packages}
    actions = {a.id: a for a in dataset.actions}
    edges = list(dataset.dependencies)
    for a in dataset.actions:
        edges.extend((a.package_id, actions[key].package_id) for key in a.prerequisites)
    for left, right in edges:
        adjacency[left].add(right)
        adjacency[right].add(left)
    remaining = set(adjacency)
    groups = []
    for root in sorted(adjacency):
        if root not in remaining:
            continue
        remaining.remove(root)
        group, stack = {root}, [root]
        while stack:
            for node in adjacency[stack.pop()]:
                if node in remaining:
                    remaining.remove(node)
                    group.add(node)
                    stack.append(node)
        groups.append(tuple(sorted(group)))
    return groups


def window_schedule(ordered, assigned, lane, capacity):
    # Earlier windows already satisfied their prerequisites.
    subset = {key for key, index in assigned.items() if index == lane}
    same_window = {
        key: replace(ordered[key], prerequisites=tuple(
            p for p in ordered[key].prerequisites if p in subset))
        for key in subset
    }
    entries, errors, _ = schedule_actions(same_window, subset, capacity)
    return entries, errors


def local_table(nodes, edges, jobs, capacities):
    graph = analyze_graph(nodes, edges)
    blocked = set(graph.blocked_nodes)
    actions = {job.id: job for job in jobs}
    options = []
    for job in jobs:
        lanes = [i for i, cap in enumerate(capacities)
                 if job.package_id not in blocked and job.duration_minutes <= cap]
        options.append(lanes if job.mandatory else [-1, *lanes])
    attempts = prod(map(len, options))
    if attempts > 100_000:
        raise PlanningLimit("A connected group exceeds 100,000 assignments; reduce group size or windows.")
    table = {}
    for placement in product(*options):
        assigned = {job.id: lane for job, lane in zip(jobs, placement) if lane >= 0}
        used = [0] * len(capacities)
        for key, lane in assigned.items():
            used[lane] += actions[key].duration_minutes
        if any(u > cap for u, cap in zip(used, capacities)):
            continue
        ordered = ordered_actions(actions, assigned, graph.transitive_prerequisites)
        if any(req not in assigned or assigned[req] > lane for key, lane in assigned.items()
               for req in ordered[key].prerequisites):
            continue
        benefit = sum(actions[key].benefit for key in assigned)
        state = tuple(used)
        if state in table and table[state].benefit >= benefit:
            continue
        # Same-window precedence must also admit an execution order.
        if all(not window_schedule(ordered, assigned, lane, cap)[1]
               for lane, cap in enumerate(capacities)):
            table[state] = Choice(benefit, tuple(sorted(assigned.items())))
    return table, graph


def combine(tables, capacities, budget):
    """Balanced divide-and-conquer; DP states are vectors of exact minutes used."""
    if len(tables) == 1:
        return tables[0]
    mid = len(tables) // 2
    left = combine(tables[:mid], capacities, budget)
    right = combine(tables[mid:], capacities, budget)
    budget[0] -= len(left) * len(right)
    if budget[0] < 0:
        raise PlanningLimit("Allocation exceeds two million combinations; reduce the instance size.")
    merged = {}
    for a, first in left.items():
        for b, second in right.items():
            state = tuple(x + y for x, y in zip(a, b))
            if any(u > cap for u, cap in zip(state, capacities)):
                continue
            score = first.benefit + second.benefit
            if state not in merged or score > merged[state].benefit:
                merged[state] = Choice(score, children=(first, second))
    return merged


class MaintenancePlanner:
    """Reuse unaffected group analyses between revisions of the same scenario."""
    def __init__(self):
        self.cache = {}

    def plan(self, dataset, capacities):
        capacities = tuple(capacities)
        if not 1 <= len(capacities) <= 4 or any(type(c) is not int or not 0 <= c <= 1440 for c in capacities):
            raise ValueError("Supply one to four integer maintenance windows of 0–1440 minutes.")
        if len(dataset.packages) > 200 or len(dataset.actions) > 200:
            raise PlanningLimit("The multiple-window planner accepts up to 200 packages and actions.")
        cache, tables, orders = {}, [], {}
        rebuilt, reused = [], []
        groups = split_groups(dataset)
        for nodes in groups:
            members = set(nodes)
            edges = tuple(sorted(e for e in dataset.dependencies if e[0] in members))
            jobs = tuple(sorted((a for a in dataset.actions if a.package_id in members), key=lambda a: a.id))
            key = nodes, edges, jobs, capacities
            if key in self.cache:
                table, graph = self.cache[key]
                reused.append(nodes)
            else:
                table, graph = local_table(*key)
                rebuilt.append(nodes)
            cache[key] = table, graph
            tables.append(table)
            orders.update(graph.transitive_prerequisites)
        self.cache = cache
        result = {"rebuilt_groups": rebuilt, "reused_groups": reused}
        total = combine(tables, capacities, [2_000_000]) if tables else {(0,) * len(capacities): Choice(0)}
        if not total:
            return dict(result, status="INFEASIBLE", windows=[], benefit=None)
        state = min(total, key=lambda s: (-total[s].benefit, sum(s), s))
        assigned = dict(recover(total[state]))
        actions = {a.id: a for a in dataset.actions}
        ordered = ordered_actions(actions, assigned, orders)
        windows = []
        for lane, cap in enumerate(capacities):
            entries, errors = window_schedule(ordered, assigned, lane, cap)
            if errors:
                raise RuntimeError("Internal reconstruction error: " + ", ".join(errors))
            windows.append(dict(capacity=cap, minutes=state[lane], schedule=entries))
        return dict(result, status="OPTIMAL", benefit=total[state].benefit, windows=windows,
                    deferred=sorted(actions.keys() - assigned.keys()))
