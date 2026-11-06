from fastapi.testclient import TestClient

from backend.main import app


def test_health() -> None:
    response = TestClient(app).get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_create_plan() -> None:
    dataset = {
        "packages": [{"id": "a"}],
        "dependencies": [],
        "actions": [{"id": "p", "package_id": "a", "duration_minutes": 5, "benefit": 10}],
    }
    response = TestClient(app).post("/api/v1/plans", json={"dataset": dataset, "window_minutes": 10})
    assert response.status_code == 200
    assert response.json()["optimization"]["selected_actions"][0]["id"] == "p"
