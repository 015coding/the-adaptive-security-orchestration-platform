from fastapi.testclient import TestClient

from app.main import create_app


def test_owner_can_create_reopen_and_run_a_blank_crystal_flow(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")

    with TestClient(app) as client:
        created = client.post("/api/crystal-flows", json={"name": "Initial assessment"})

        assert created.status_code == 201
        flow = created.json()
        assert flow == {
            "id": flow["id"],
            "name": "Initial assessment",
            "version": 1,
            "nodes": [],
            "edges": [],
        }

        reopened = client.get(f"/api/crystal-flows/{flow['id']}")
        assert reopened.status_code == 200
        assert reopened.json() == flow

        listed = client.get("/api/crystal-flows")
        assert listed.status_code == 200
        assert listed.json() == [flow]

        started = client.post(f"/api/crystal-flows/{flow['id']}/runs")
        assert started.status_code == 201
        run = started.json()
        assert run["crystalFlowId"] == flow["id"]
        assert run["status"] == "created"

        audit = client.get(f"/api/runs/{run['id']}/audit")
        assert audit.status_code == 200
        assert audit.json() == [
            {
                "eventType": "run.created",
                "runId": run["id"],
                "crystalFlowId": flow["id"],
            }
        ]


def test_owner_cannot_create_a_crystal_flow_with_a_whitespace_only_name(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")

    with TestClient(app) as client:
        response = client.post("/api/crystal-flows", json={"name": "   "})

    assert response.status_code == 422
