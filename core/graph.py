from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class GraphAnalysis:
    nodes: list[str]
    edges: list[dict[str, str]]
    components: list[list[str]]
    cyclic_components: list[list[str]]
    component_of: dict[str, int]
    condensation_edges: list[dict[str, str]]
    topological_order: list[str]
    trace: list[dict[str, object]]
    direct_prerequisites: dict[str, list[str]] = field(default_factory=dict)
    transitive_prerequisites: dict[str, list[str]] = field(default_factory=dict)
    dependents: dict[str, list[str]] = field(default_factory=dict)
    depth: dict[str, int] = field(default_factory=dict)
    blocked_nodes: list[str] = field(default_factory=list)

    @property
    def component_ids(self) -> dict[str, str]:
        return {node: f"component-{component}" for node, component in self.component_of.items()}


def analyze_graph(nodes: tuple[str, ...], dependencies: tuple[tuple[str, str], ...]) -> GraphAnalysis:
    """Analyze package edges where ``dependent -> prerequisite``.

    SCC detection is direction-independent, while execution order is returned
    with prerequisites before dependents.
    """
    adjacency = {node: [] for node in nodes}
    for source, target in dependencies:
        if source not in adjacency or target not in adjacency:
            raise ValueError(f"Dependency references unknown package: {source}->{target}")
        adjacency[source].append(target)
    for values in adjacency.values():
        values.sort()

    index = 0
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []
    trace: list[dict[str, object]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlink[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        trace.append({"algorithm": "tarjan", "event": "discover", "node": node, "index": indices[node]})
        for neighbor in adjacency[node]:
            if neighbor not in indices:
                visit(neighbor)
                lowlink[node] = min(lowlink[node], lowlink[neighbor])
                trace.append({"algorithm": "tarjan", "event": "lowlink_update", "node": node, "value": lowlink[node]})
            elif neighbor in on_stack:
                lowlink[node] = min(lowlink[node], indices[neighbor])
        if lowlink[node] == indices[node]:
            component: list[str] = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == node:
                    break
            component.sort()
            components.append(component)
            trace.append({"algorithm": "tarjan", "event": "component", "nodes": component})

    for node in sorted(nodes):
        if node not in indices:
            visit(node)

    component_of = {node: position for position, component in enumerate(components) for node in component}
    cyclic_components = [
        component for component in components
        if len(component) > 1 or any(source == target == component[0] for source, target in dependencies)
    ]
    condensation: set[tuple[int, int]] = set()
    for source, target in dependencies:
        left, right = component_of[source], component_of[target]
        if left != right:
            condensation.add((left, right))
    condensation_edges = [
        {"from": f"component-{source}", "to": f"component-{target}"}
        for source, target in sorted(condensation)
    ]

    # Stored edges point from a dependent to its prerequisite. Reverse them
    # for prerequisite-first Kahn ordering.
    indegree = {position: 0 for position in range(len(components))}
    component_adjacency = {position: [] for position in range(len(components))}
    for source, target in sorted(condensation):
        component_adjacency[target].append(source)
        indegree[source] += 1
    ready = sorted(position for position, degree in indegree.items() if degree == 0)
    component_order: list[int] = []
    while ready:
        current = ready.pop(0)
        component_order.append(current)
        trace.append({"algorithm": "topological_sort", "event": "process", "component": f"component-{current}"})
        for neighbor in component_adjacency[current]:
            indegree[neighbor] -= 1
            if indegree[neighbor] == 0:
                ready.append(neighbor)
                ready.sort()
                trace.append({"algorithm": "topological_sort", "event": "ready", "component": f"component-{neighbor}"})
    if len(component_order) != len(components):
        raise ValueError("Condensation graph is not acyclic")
    topological_order = [node for component_id in component_order for node in components[component_id]]
    reverse = {node: [] for node in nodes}
    for source, target in dependencies:
        reverse[target].append(source)
    for values in reverse.values():
        values.sort()
    direct_prerequisites = {node: sorted(adjacency[node]) for node in nodes}
    transitive_prerequisites = {
        node: sorted(_traverse(node, adjacency)) for node in nodes
    }
    dependents = {node: sorted(_traverse(node, reverse)) for node in nodes}
    depth = {node: 0 for node in nodes}
    for node in topological_order:
        if adjacency[node]:
            depth[node] = max(depth[prerequisite] + 1 for prerequisite in adjacency[node])
    blocked_nodes = sorted({
        node
        for component in cyclic_components
        for cyclic_node in component
        for node in [cyclic_node, *dependents[cyclic_node]]
    })
    return GraphAnalysis(
        nodes=list(nodes),
        edges=[{"from": source, "to": target} for source, target in dependencies],
        components=components,
        cyclic_components=cyclic_components,
        component_of=component_of,
        condensation_edges=condensation_edges,
        topological_order=topological_order,
        trace=trace,
        direct_prerequisites=direct_prerequisites,
        transitive_prerequisites=transitive_prerequisites,
        dependents=dependents,
        depth=depth,
        blocked_nodes=blocked_nodes,
    )


def _traverse(start: str, adjacency: dict[str, list[str]]) -> set[str]:
    visited: set[str] = set()
    queue: deque[str] = deque(adjacency[start])
    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        queue.extend(adjacency[current])
    return visited


def bfs_dependencies(nodes: Iterable[str], dependencies: Iterable[tuple[str, str]], start: str) -> list[str]:
    """Return deterministic breadth-first reachable nodes.

    The supplied edges use ``dependent -> prerequisite``. This function
    traverses in the stored direction, so it answers prerequisite reachability.
    """
    adjacency = _validated_adjacency(tuple(nodes), tuple(dependencies))
    if start not in adjacency:
        raise ValueError(f"Unknown graph node: {start}")
    result: list[str] = []
    seen = {start}
    queue: deque[str] = deque([start])
    while queue:
        current = queue.popleft()
        for neighbor in adjacency[current]:
            if neighbor not in seen:
                seen.add(neighbor)
                result.append(neighbor)
                queue.append(neighbor)
    return result


def dfs_dependencies(nodes: Iterable[str], dependencies: Iterable[tuple[str, str]], start: str) -> list[str]:
    """Return deterministic depth-first prerequisite traversal."""
    adjacency = _validated_adjacency(tuple(nodes), tuple(dependencies))
    if start not in adjacency:
        raise ValueError(f"Unknown graph node: {start}")
    result: list[str] = []
    seen = {start}

    def visit(node: str) -> None:
        for neighbor in adjacency[node]:
            if neighbor not in seen:
                seen.add(neighbor)
                result.append(neighbor)
                visit(neighbor)

    visit(start)
    return result


def _validated_adjacency(nodes: tuple[str, ...], dependencies: tuple[tuple[str, str], ...]) -> dict[str, list[str]]:
    adjacency = {node: [] for node in nodes}
    for source, target in dependencies:
        if source not in adjacency or target not in adjacency:
            raise ValueError(f"Dependency references unknown package: {source}->{target}")
        adjacency[source].append(target)
    for values in adjacency.values():
        values.sort()
    return adjacency


def graph_contract(analysis: GraphAnalysis) -> dict[str, object]:
    """Build a frontend-independent graph JSON contract."""
    cyclic_ids = {f"component-{analysis.component_of[node]}" for component in analysis.cyclic_components for node in component}
    nodes = [
        {
            "id": node,
            "type": "package",
            "component_id": analysis.component_ids[node],
            "is_cyclic": analysis.component_ids[node] in cyclic_ids,
            "is_blocked": node in analysis.blocked_nodes,
            "dependency_depth": analysis.depth[node],
            "direct_prerequisites": analysis.direct_prerequisites[node],
            "transitive_prerequisites": analysis.transitive_prerequisites[node],
            "dependents": analysis.dependents[node],
        }
        for node in analysis.nodes
    ]
    edges = [
        {"id": f"{edge['from']}->{edge['to']}", "from": edge["from"], "to": edge["to"], "type": "package_dependency"}
        for edge in analysis.edges
    ]
    return {
        "nodes": nodes,
        "edges": edges,
        "components": [
            {
                "id": f"component-{index}",
                "nodes": component,
                "is_cyclic": component in analysis.cyclic_components,
                "is_blocked": any(node in analysis.blocked_nodes for node in component),
                "explanation": "Cycle requires resolution before affected packages can be planned." if component in analysis.cyclic_components else None,
            }
            for index, component in enumerate(analysis.components)
        ],
        "analysis": {
            "topological_order": analysis.topological_order,
            "blocked_nodes": analysis.blocked_nodes,
            "cycle_count": len(analysis.cyclic_components),
            "node_count": len(analysis.nodes),
            "edge_count": len(analysis.edges),
        },
    }
