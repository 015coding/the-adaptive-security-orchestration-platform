from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.main import create_app
from app.vm_runner import VmCommandResult


class ControlledVmRunner:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def execute(
        self, *, environment: str, workspace: str, command: list[str], timeout_seconds: int
    ) -> VmCommandResult:
        self.calls.append(
            {
                "environment": environment,
                "workspace": workspace,
                "command": command,
                "timeout_seconds": timeout_seconds,
            }
        )
        return VmCommandResult(exit_code=0, stdout="target discovered", stderr="")


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


def test_owner_can_save_a_new_immutable_crystal_flow_graph_version(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")

    with TestClient(app) as client:
        created = client.post("/api/crystal-flows", json={"name": "API assessment"}).json()
        saved = client.put(
            f"/api/crystal-flows/{created['id']}",
            json={
                "nodes": [
                    {
                        "id": "recon-1",
                        "type": "recon-agent",
                        "label": "Discover API surface",
                        "position": {"x": 80, "y": 80},
                        "config": {"target": "https://lab.example.test"},
                    },
                    {
                        "id": "verify-1",
                        "type": "verification-step",
                        "label": "Verify result",
                        "position": {"x": 360, "y": 80},
                        "config": {},
                    },
                ],
                "edges": [{"id": "recon-to-verify", "source": "recon-1", "target": "verify-1"}],
            },
        )

        assert saved.status_code == 200
        assert saved.json()["version"] == 2
        assert saved.json()["nodes"][0]["label"] == "Discover API surface"
        assert saved.json()["edges"] == [
            {"id": "recon-to-verify", "source": "recon-1", "target": "verify-1"}
        ]

        reopened = client.get(f"/api/crystal-flows/{created['id']}")
        assert reopened.status_code == 200
        assert reopened.json() == saved.json()

        original = client.get(f"/api/crystal-flows/{created['id']}/versions/1")
        assert original.status_code == 200
        assert original.json()["version"] == 1
        assert original.json()["nodes"] == []
        assert original.json()["edges"] == []


def test_owner_cannot_save_a_branch_to_a_missing_workflow_node(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")

    with TestClient(app) as client:
        created = client.post("/api/crystal-flows", json={"name": "Invalid graph"}).json()
        saved = client.put(
            f"/api/crystal-flows/{created['id']}",
            json={
                "nodes": [
                    {
                        "id": "recon-1",
                        "type": "recon-agent",
                        "label": "Recon",
                        "position": {"x": 0, "y": 0},
                        "config": {},
                    }
                ],
                "edges": [{"id": "invalid", "source": "recon-1", "target": "missing"}],
            },
        )

    assert saved.status_code == 422


def test_owner_cannot_save_an_unapproved_workflow_node_type(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")

    with TestClient(app) as client:
        created = client.post("/api/crystal-flows", json={"name": "Unapproved node"}).json()
        saved = client.put(
            f"/api/crystal-flows/{created['id']}",
            json={
                "nodes": [
                    {
                        "id": "unknown-1",
                        "type": "unapproved-agent",
                        "label": "Unapproved",
                        "position": {"x": 0, "y": 0},
                        "config": {},
                    }
                ],
                "edges": [],
            },
        )

    assert saved.status_code == 422


def test_permitted_vm_task_runs_in_the_scope_workspace_and_returns_a_host_log_bundle(tmp_path):
    runner = ControlledVmRunner()
    app = create_app(database_path=tmp_path / "platform.db", vm_runner=runner)
    now = datetime.now(UTC)

    with TestClient(app) as client:
        scope = client.post(
            "/api/scopes",
            json={
                "targets": ["https://lab.example.test"],
                "workspace": "/srv/adaptive-security/runs/run-1",
                "allowedActions": ["reconnaissance"],
                "resourceLimits": {
                    "maxRequestsPerSecond": 5,
                    "maxConcurrentTasks": 1,
                    "maxRuntimeSeconds": 600,
                },
                "startsAt": now.isoformat(),
                "expiresAt": (now + timedelta(hours=1)).isoformat(),
                "unattendedExecution": False,
                "authorizedLabEnvironment": True,
            },
        ).json()
        task = client.post(
            "/api/vm-tasks",
            json={
                "scopeId": scope["id"],
                "environment": "kali",
                "target": "https://lab.example.test",
                "action": "reconnaissance",
                "command": ["nmap", "--version"],
                "artifactReferences": ["output/recon.json"],
            },
        )

        assert task.status_code == 201
        assert task.json() == {
            "id": task.json()["id"],
            "scopeId": scope["id"],
            "environment": "kali",
            "workspace": "/srv/adaptive-security/runs/run-1",
            "status": "completed",
            "exitCode": 0,
            "stdout": "target discovered",
            "stderr": "",
            "artifactReferences": ["output/recon.json"],
        }
        assert runner.calls == [
            {
                "environment": "kali",
                "workspace": "/srv/adaptive-security/runs/run-1",
                "command": ["nmap", "--version"],
                "timeout_seconds": 600,
            }
        ]

        logs = client.get(f"/api/scopes/{scope['id']}/run-log-bundles")
        assert logs.status_code == 200
        assert logs.json() == [task.json()]


def test_out_of_scope_vm_task_is_blocked_without_calling_the_vm_runner(tmp_path):
    runner = ControlledVmRunner()
    app = create_app(database_path=tmp_path / "platform.db", vm_runner=runner)
    now = datetime.now(UTC)

    with TestClient(app) as client:
        scope = client.post(
            "/api/scopes",
            json={
                "targets": ["https://lab.example.test"],
                "workspace": "/srv/adaptive-security/runs/run-1",
                "allowedActions": ["reconnaissance"],
                "resourceLimits": {
                    "maxRequestsPerSecond": 5,
                    "maxConcurrentTasks": 1,
                    "maxRuntimeSeconds": 600,
                },
                "startsAt": now.isoformat(),
                "expiresAt": (now + timedelta(hours=1)).isoformat(),
                "unattendedExecution": False,
                "authorizedLabEnvironment": True,
            },
        ).json()
        task = client.post(
            "/api/vm-tasks",
            json={
                "scopeId": scope["id"],
                "environment": "kali",
                "target": "https://outside.example.test",
                "action": "reconnaissance",
                "command": ["nmap", "--version"],
                "artifactReferences": [],
            },
        )

    assert task.status_code == 201
    assert task.json()["status"] == "blocked"
    assert task.json()["stderr"] == "target is outside Scope"
    assert runner.calls == []


def test_owner_cannot_create_a_crystal_flow_with_a_whitespace_only_name(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")

    with TestClient(app) as client:
        response = client.post("/api/crystal-flows", json={"name": "   "})

    assert response.status_code == 422


def test_policy_engine_allows_a_scoped_safe_action_and_records_the_decision(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")
    now = datetime.now(UTC)

    with TestClient(app) as client:
        scope = client.post(
            "/api/scopes",
            json={
                "targets": ["https://lab.example.test"],
                "workspace": "/srv/adaptive-security/runs/run-1",
                "allowedActions": ["reconnaissance"],
                "resourceLimits": {
                    "maxRequestsPerSecond": 5,
                    "maxConcurrentTasks": 1,
                    "maxRuntimeSeconds": 600,
                },
                "startsAt": now.isoformat(),
                "expiresAt": (now + timedelta(hours=1)).isoformat(),
                "unattendedExecution": False,
                "authorizedLabEnvironment": True,
            },
        )
        assert scope.status_code == 201

        decision = client.post(
            "/api/policy-decisions",
            json={
                "scopeId": scope.json()["id"],
                "target": "https://lab.example.test",
                "action": "reconnaissance",
            },
        )

        assert decision.status_code == 201
        assert decision.json() == {
            "id": decision.json()["id"],
            "scopeId": scope.json()["id"],
            "target": "https://lab.example.test",
            "action": "reconnaissance",
            "status": "allow",
            "reason": "action is permitted by Scope",
        }

        recorded = client.get(f"/api/scopes/{scope.json()['id']}/policy-decisions")
        assert recorded.status_code == 200
        assert recorded.json() == [decision.json()]


def test_policy_engine_denies_an_out_of_scope_target_and_records_the_reason(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")
    now = datetime.now(UTC)

    with TestClient(app) as client:
        scope = client.post(
            "/api/scopes",
            json={
                "targets": ["https://lab.example.test"],
                "workspace": "/srv/adaptive-security/runs/run-1",
                "allowedActions": ["reconnaissance"],
                "resourceLimits": {
                    "maxRequestsPerSecond": 5,
                    "maxConcurrentTasks": 1,
                    "maxRuntimeSeconds": 600,
                },
                "startsAt": now.isoformat(),
                "expiresAt": (now + timedelta(hours=1)).isoformat(),
                "unattendedExecution": False,
                "authorizedLabEnvironment": True,
            },
        )

        decision = client.post(
            "/api/policy-decisions",
            json={
                "scopeId": scope.json()["id"],
                "target": "https://outside.example.test",
                "action": "reconnaissance",
            },
        )

    assert decision.status_code == 201
    assert decision.json()["status"] == "deny"
    assert decision.json()["reason"] == "target is outside Scope"


def test_policy_engine_denies_an_action_not_permitted_by_scope(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")
    now = datetime.now(UTC)

    with TestClient(app) as client:
        scope = client.post(
            "/api/scopes",
            json={
                "targets": ["https://lab.example.test"],
                "workspace": "/srv/adaptive-security/runs/run-1",
                "allowedActions": ["reconnaissance"],
                "resourceLimits": {
                    "maxRequestsPerSecond": 5,
                    "maxConcurrentTasks": 1,
                    "maxRuntimeSeconds": 600,
                },
                "startsAt": now.isoformat(),
                "expiresAt": (now + timedelta(hours=1)).isoformat(),
                "unattendedExecution": False,
                "authorizedLabEnvironment": True,
            },
        )
        decision = client.post(
            "/api/policy-decisions",
            json={
                "scopeId": scope.json()["id"],
                "target": "https://lab.example.test",
                "action": "exploitation-attempt",
            },
        )

    assert decision.status_code == 201
    assert decision.json()["status"] == "deny"
    assert decision.json()["reason"] == "action is not permitted by Scope"


def test_policy_engine_requires_approval_for_a_permitted_exploitation_attempt(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")
    now = datetime.now(UTC)

    with TestClient(app) as client:
        scope = client.post(
            "/api/scopes",
            json={
                "targets": ["https://lab.example.test"],
                "workspace": "/srv/adaptive-security/runs/run-1",
                "allowedActions": ["exploitation-attempt"],
                "resourceLimits": {
                    "maxRequestsPerSecond": 1,
                    "maxConcurrentTasks": 1,
                    "maxRuntimeSeconds": 60,
                },
                "startsAt": now.isoformat(),
                "expiresAt": (now + timedelta(hours=1)).isoformat(),
                "unattendedExecution": False,
                "authorizedLabEnvironment": True,
            },
        )
        decision = client.post(
            "/api/policy-decisions",
            json={
                "scopeId": scope.json()["id"],
                "target": "https://lab.example.test",
                "action": "exploitation-attempt",
            },
        )

    assert decision.status_code == 201
    assert decision.json()["status"] == "approval-required"
    assert decision.json()["reason"] == "Exploitation Attempt requires Approval"


def test_policy_engine_denies_actions_after_the_scope_window_expires(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")
    now = datetime.now(UTC)

    with TestClient(app) as client:
        scope = client.post(
            "/api/scopes",
            json={
                "targets": ["https://lab.example.test"],
                "workspace": "/srv/adaptive-security/runs/run-1",
                "allowedActions": ["reconnaissance"],
                "resourceLimits": {
                    "maxRequestsPerSecond": 5,
                    "maxConcurrentTasks": 1,
                    "maxRuntimeSeconds": 600,
                },
                "startsAt": (now - timedelta(hours=2)).isoformat(),
                "expiresAt": (now - timedelta(hours=1)).isoformat(),
                "unattendedExecution": False,
                "authorizedLabEnvironment": True,
            },
        )
        decision = client.post(
            "/api/policy-decisions",
            json={
                "scopeId": scope.json()["id"],
                "target": "https://lab.example.test",
                "action": "reconnaissance",
            },
        )

    assert decision.status_code == 201
    assert decision.json()["status"] == "deny"
    assert decision.json()["reason"] == "Scope Window has expired"


def test_scope_creation_rejects_incomplete_scope_input(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")

    with TestClient(app) as client:
        response = client.post("/api/scopes", json={"targets": ["https://lab.example.test"]})

    assert response.status_code == 422
