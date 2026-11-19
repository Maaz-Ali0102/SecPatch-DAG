from dataclasses import replace
from itertools import product
import random

from fastapi.testclient import TestClient
from backend.main import app
from core.cep import experiment
from core.engine import run_analysis
from core.maintenance import MaintenancePlanner
from core.models import Dataset, PatchAction


def test_package_import_orders_selected_actions_only_on_same_asset():
    consumer = PatchAction("web", "app", 1, 20, 20, asset_id="api")
    provider = PatchAction("lib", "base", 1, 1, 1, asset_id="api")
    data = Dataset(("app", "base"), (("app", "base"),), (consumer, provider))
    order = lambda d: [a["action_id"] for a in run_analysis(d, 2)["schedule"]["entries"]]
    assert order(data) == ["lib", "web"]
    assert order(replace(data, actions=(consumer, replace(provider, asset_id="other")))) == ["web", "lib"]
    assert run_analysis(data, 1)["optimization"]["selected_actions"][0]["id"] == "web"


def test_mandatory_status_and_approximation_scope():
    a = PatchAction("a", "app", 2, 2, 2, mandatory=True)
    d = Dataset(("app",), (), (a,))
    assert run_analysis(d, 1)["optimization"]["solver_status"] == "INFEASIBLE"
    assert not run_analysis(d, 2)["optimization"]["half_bound_applies"]
    assert run_analysis(replace(d, actions=(replace(a, mandatory=False),)), 2)["optimization"]["half_bound_applies"]


def test_shared_actions_compete_across_distinct_windows_and_oversize_is_excluded():
    actions = tuple(PatchAction(x, x, duration, benefit, 1)
                    for x, duration, benefit in [("a", 2, 6), ("b", 3, 8), ("c", 3, 7), ("heavy", 6, 99)])
    d = Dataset(tuple(a.id for a in actions), (), actions)
    r = MaintenancePlanner().plan(d, (2, 3))
    assert r["benefit"] == 14 and r["deferred"] == ["c", "heavy"]
    assert [w["schedule"][0]["action_id"] for w in r["windows"]] == ["a", "b"]


def test_worked_experiment_and_endpoint():
    r = experiment()
    assert [r[key]["benefit"] for key in ("baseline", "sensitivity", "incremental")] == [82, 78, 71]
    assert len(r["incremental"]["rebuilt_groups"]) == 1 and len(r["incremental"]["reused_groups"]) == 2
    client = TestClient(app)
    assert client.get("/api/v1/cep/experiment").json()["baseline"]["benefit"] == 82
    assert client.get("/api/v1/cep/experiment?first=-1").status_code == 422


def test_exactness_against_independent_enumeration_with_cross_window_precedence():
    rng = random.Random(47)
    for _ in range(35):
        jobs = tuple(PatchAction(str(i), str(i), rng.randint(1, 5), rng.randint(1, 9), 1,
                                 ("0",) if i == 2 else (), mandatory=i == 3)
                     for i in range(4))
        caps = (rng.randint(0, 5), rng.randint(1, 6))
        data = Dataset(tuple(a.id for a in jobs), (("1", "0"),), jobs)
        expected = None
        for lanes in product((-1, 0, 1), repeat=4):
            if lanes[3] < 0 or (lanes[2] >= 0 and not 0 <= lanes[0] <= lanes[2]):
                continue
            if lanes[1] >= 0 and lanes[0] > lanes[1]:
                continue
            if any(sum(a.duration_minutes for a, lane in zip(jobs, lanes) if lane == i) > cap
                   for i, cap in enumerate(caps)):
                continue
            benefit = sum(a.benefit for a, lane in zip(jobs, lanes) if lane >= 0)
            expected = max(benefit, expected or 0)
        result = MaintenancePlanner().plan(data, caps)
        assert result["benefit"] == expected


def test_cache_handles_group_split_and_capacity_change():
    planner = MaintenancePlanner()
    jobs = (PatchAction("a", "a", 1, 1, 1), PatchAction("b", "b", 1, 2, 1))
    d = Dataset(("a", "b"), (("a", "b"), ("b", "a")), jobs)
    assert planner.plan(d, (2,))["benefit"] == 0
    no_edges = replace(d, dependencies=())
    assert planner.plan(no_edges, (2,))["benefit"] == 3
    assert planner.plan(no_edges, (1,))["benefit"] == 2


def test_replan_saved_snapshot_via_api(monkeypatch):
    import backend.main as api
    from contextlib import nullcontext
    from uuid import uuid4
    dataset = {"packages": ["app"], "actions": [
        {"id": "x", "package_id": "app", "duration_minutes": 8, "benefit": 9}]}
    monkeypatch.setattr(api, "session_scope", nullcontext)
    monkeypatch.setattr(api, "get_analysis", lambda session, key: {"persistence": {"input_snapshot": dataset}})
    response = TestClient(app).get(f"/api/v1/analysis-runs/{uuid4()}/maintenance-windows?first=3&second=8")
    assert response.status_code == 200
    plan = response.json()
    assert plan["benefit"] == 9
    assert plan["windows"][1]["schedule"][0]["action_id"] == "x"
