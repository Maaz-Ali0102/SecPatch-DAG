import pytest

from core.graph import analyze_graph, bfs_dependencies, dfs_dependencies, graph_contract


def test_empty_graph_contract() -> None:
    analysis = analyze_graph((), ())
    contract = graph_contract(analysis)
    assert contract["nodes"] == []
    assert contract["edges"] == []
    assert contract["analysis"]["topological_order"] == []


def test_single_node_and_isolated_components() -> None:
    analysis = analyze_graph(("solo", "other"), ())
    assert analysis.topological_order == ["other", "solo"]
    assert analysis.depth == {"solo": 0, "other": 0}
    assert analysis.cyclic_components == []


def test_linear_chain_traversal_depth_and_metadata() -> None:
    nodes = ("app", "lib", "db")
    edges = (("app", "lib"), ("lib", "db"))
    analysis = analyze_graph(nodes, edges)
    assert analysis.topological_order == ["db", "lib", "app"]
    assert analysis.depth == {"app": 2, "lib": 1, "db": 0}
    assert bfs_dependencies(nodes, edges, "app") == ["lib", "db"]
    assert dfs_dependencies(nodes, edges, "app") == ["lib", "db"]
    assert analysis.transitive_prerequisites["app"] == ["db", "lib"]
    assert analysis.dependents["db"] == ["app", "lib"]
    assert graph_contract(analysis)["nodes"][0]["type"] == "package"


def test_branching_and_multiple_prerequisites_are_deterministic() -> None:
    nodes = ("app", "lib-a", "lib-b", "common")
    edges = (("app", "lib-b"), ("app", "lib-a"), ("lib-a", "common"), ("lib-b", "common"))
    first = analyze_graph(nodes, edges)
    second = analyze_graph(nodes, edges)
    assert first.topological_order == second.topological_order
    assert first.direct_prerequisites["app"] == ["lib-a", "lib-b"]
    assert first.transitive_prerequisites["app"] == ["common", "lib-a", "lib-b"]
    assert first.dependents["common"] == ["app", "lib-a", "lib-b"]


def test_self_loop_multiple_sccs_and_transitive_blocking() -> None:
    nodes = ("cycle-a", "cycle-b", "self", "consumer", "safe")
    edges = (("cycle-a", "cycle-b"), ("cycle-b", "cycle-a"), ("self", "self"), ("consumer", "cycle-a"))
    analysis = analyze_graph(nodes, edges)
    assert sorted(analysis.cyclic_components) == [["cycle-a", "cycle-b"], ["self"]]
    assert analysis.blocked_nodes == ["consumer", "cycle-a", "cycle-b", "self"]
    contract = graph_contract(analysis)
    blocked = {node["id"] for node in contract["nodes"] if node["is_blocked"]}
    assert blocked == {"consumer", "cycle-a", "cycle-b", "self"}
    assert any(component["is_cyclic"] and component["explanation"] for component in contract["components"])


def test_missing_dependency_reference_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown package"):
        analyze_graph(("a",), (("a", "missing"),))


def test_traversal_unknown_start_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown graph node"):
        bfs_dependencies(("a",), (), "missing")
