from datetime import UTC, datetime, timedelta
from hashlib import sha256

from fastapi.testclient import TestClient

from app.main import create_app
from app.session_adapter import CodexCliResult, CodexCliTimeout
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


class ControlledCodexCli:
    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []

    def execute(self, request: dict[str, object], timeout_seconds: int) -> CodexCliResult:
        self.requests.append({"request": request, "timeout_seconds": timeout_seconds})
        return CodexCliResult(
            output={"summary": "API surface identified", "nextBranch": "verify"},
            resource_units=4,
        )


class TimingOutCodexCli:
    def execute(self, request: dict[str, object], timeout_seconds: int) -> CodexCliResult:
        raise CodexCliTimeout("Codex CLI session exceeded Node Timeout")


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


def test_finding_reconstructs_run_provenance_and_keeps_sensitive_vm_evidence_masked(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")
    raw_summary = "token=super-secret"
    now = datetime.now(UTC)

    with TestClient(app) as client:
        flow = client.post("/api/crystal-flows", json={"name": "Evidence flow"}).json()
        client.put(
            f"/api/crystal-flows/{flow['id']}",
            json={
                "nodes": [{"id": "recon", "type": "recon-agent", "label": "Recon", "position": {"x": 0, "y": 0}, "config": {}}],
                "edges": [],
            },
        )
        run = client.post(f"/api/crystal-flows/{flow['id']}/runs").json()
        client.post(
            f"/api/runs/{run['id']}/node-results",
            json={"nodeId": "recon", "trigger": "evidence", "result": {"endpoint": "/admin"}},
        )
        evidence = client.post(
            "/api/evidence-records",
            json={
                "runId": run["id"],
                "target": "https://lab.example.test",
                "summary": raw_summary,
                "sha256": sha256(raw_summary.encode()).hexdigest(),
                "storage": "vm-resident",
                "vmResidentPath": "artifacts/memory.raw",
                "availability": "available",
                "sensitive": True,
            },
        )
        scope = client.post(
            "/api/scopes",
            json={
                "targets": ["https://lab.example.test"],
                "workspace": "/srv/adaptive-security/runs/evidence",
                "allowedActions": ["reconnaissance"],
                "resourceLimits": {"maxRequestsPerSecond": 1, "maxConcurrentTasks": 1, "maxRuntimeSeconds": 60},
                "startsAt": now.isoformat(),
                "expiresAt": (now + timedelta(hours=1)).isoformat(),
                "unattendedExecution": False,
                "authorizedLabEnvironment": True,
            },
        ).json()
        tool_call = client.post(
            "/api/vm-tasks",
            json={
                "scopeId": scope["id"],
                "environment": "kali",
                "target": "https://lab.example.test",
                "action": "reconnaissance",
                "command": ["echo", "evidence"],
                "artifactReferences": ["artifacts/recon.json"],
            },
        ).json()
        policy_decision = client.post(
            "/api/policy-decisions",
            json={"scopeId": scope["id"], "target": "https://lab.example.test", "action": "reconnaissance"},
        ).json()
        finding = client.post(
            "/api/findings",
            json={
                "title": "Administrative endpoint exposed",
                "target": "https://lab.example.test",
                "runId": run["id"],
                "evidenceRecordIds": [evidence.json()["id"]],
                "runLogBundleIds": [tool_call["id"]],
                "policyDecisionIds": [policy_decision["id"]],
            },
        )
        masked = client.get(f"/api/evidence-records/{evidence.json()['id']}")
        revealed = client.post(f"/api/evidence-records/{evidence.json()['id']}/reveal")
        access_events = client.get(f"/api/evidence-records/{evidence.json()['id']}/access-events")
        messages = client.get(f"/api/runs/{run['id']}/agent-messages")
        findings = client.get(f"/api/runs/{run['id']}/findings")

    assert evidence.status_code == 201
    assert finding.status_code == 201
    assert finding.json()["provenance"]["nodeIds"] == ["recon"]
    assert finding.json()["provenance"]["agentMessages"] == [{"sourceNodeId": "recon", "trigger": "evidence", "message": {"endpoint": "/admin"}}]
    assert finding.json()["provenance"]["toolCalls"][0]["id"] == tool_call["id"]
    assert finding.json()["provenance"]["policyDecisions"][0]["id"] == policy_decision["id"]
    assert finding.json()["provenance"]["evidenceArtifacts"][0]["sha256"] == sha256(raw_summary.encode()).hexdigest()
    assert masked.json()["summary"] == "[Sensitive Evidence masked]"
    assert masked.json()["vmResidentPath"] == "artifacts/memory.raw"
    assert revealed.json()["summary"] == raw_summary
    assert access_events.json() == [{"eventType": "evidence.revealed"}]
    assert messages.json() == [{"sourceNodeId": "recon", "targetNodeId": None, "trigger": "evidence", "message": {"endpoint": "/admin"}}]
    assert [item["id"] for item in findings.json()] == [finding.json()["id"]]


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


def test_owner_can_admit_a_trusted_builtin_and_checksum_approved_external_plugin(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")
    manifest = {
        "capabilities": ["api-review"],
        "permissions": ["network.read"],
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "object"},
    }

    with TestClient(app) as client:
        builtin = client.post(
            "/api/plugins",
            json={"name": "Built-in API Review", "version": "1.0.0", "builtin": True, "manifest": manifest},
        )
        external = client.post(
            "/api/plugins",
            json={
                "name": "External API Review",
                "version": "1.0.0",
                "builtin": False,
                "checksum": "a" * 64,
                "ownerApproved": True,
                "manifest": manifest,
            },
        )
        untrusted = client.post(
            "/api/plugins",
            json={"name": "Untrusted Plugin", "version": "1.0.0", "builtin": False, "manifest": manifest},
        )
        listed = client.get("/api/plugins")

    assert builtin.status_code == 201
    assert builtin.json()["status"] == "approved"
    assert builtin.json()["integrityVerified"] is True
    assert external.status_code == 201
    assert external.json()["status"] == "approved"
    assert external.json()["integrityVerified"] is True
    assert untrusted.status_code == 422
    assert [plugin["id"] for plugin in listed.json()] == [builtin.json()["id"], external.json()["id"]]


def test_owner_can_create_a_governed_custom_agent_and_enable_its_plugin_in_a_crystal_flow(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")
    manifest = {
        "capabilities": ["api-review"],
        "permissions": ["network.read"],
        "inputSchema": {"type": "object"},
        "outputSchema": {"type": "object"},
    }
    agent = {
        "name": "API Specialist",
        "objective": "Review the permitted API surface.",
        "instructions": "Use only the declared capability.",
        "inputs": {"target": "https://lab.example.test"},
        "capabilities": ["api-review"],
        "permissions": ["network.read"],
        "executionLimits": {"maxAttempts": 2, "maxRuntimeSeconds": 60},
    }

    with TestClient(app) as client:
        plugin = client.post(
            "/api/plugins",
            json={"name": "Built-in API Review", "version": "1.0.0", "builtin": True, "manifest": manifest},
        ).json()
        custom_agent = client.post("/api/custom-agents", json={**agent, "pluginId": plugin["id"]})
        code_attempt = client.post("/api/custom-agents", json={**agent, "pluginId": plugin["id"], "code": "print(1)"})
        flow = client.post("/api/crystal-flows", json={"name": "Custom API review"}).json()
        unenabled = client.put(
            f"/api/crystal-flows/{flow['id']}",
            json={
                "nodes": [{"id": "agent", "type": "custom-agent", "label": "API Specialist", "position": {"x": 0, "y": 0}, "config": {"customAgentId": custom_agent.json()["id"]}}],
                "edges": [],
            },
        )
        enabled = client.post(f"/api/crystal-flows/{flow['id']}/plugins", json={"pluginId": plugin["id"]})
        enabled_plugins = client.get(f"/api/crystal-flows/{flow['id']}/plugins")
        saved = client.put(
            f"/api/crystal-flows/{flow['id']}",
            json={
                "nodes": [{"id": "agent", "type": "custom-agent", "label": "API Specialist", "position": {"x": 0, "y": 0}, "config": {"customAgentId": custom_agent.json()["id"]}}],
                "edges": [],
            },
        )

    assert custom_agent.status_code == 201
    assert code_attempt.status_code == 422
    assert unenabled.status_code == 422
    assert enabled.status_code == 200
    assert enabled.json()["version"] == 2
    assert [item["id"] for item in enabled_plugins.json()] == [plugin["id"]]
    assert saved.status_code == 200
    assert saved.json()["version"] == 3


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


def test_ai_node_uses_the_session_adapter_and_records_output_timeout_and_resource_use(tmp_path):
    codex_cli = ControlledCodexCli()
    app = create_app(database_path=tmp_path / "platform.db", codex_cli=codex_cli)

    with TestClient(app) as client:
        flow = client.post("/api/crystal-flows", json={"name": "AI assessment"}).json()
        run = client.post(f"/api/crystal-flows/{flow['id']}/runs").json()
        invocation = client.post(
            f"/api/runs/{run['id']}/ai-nodes",
            json={
                "nodeId": "recon-1",
                "task": "Identify the API surface",
                "input": {"target": "https://lab.example.test"},
                "timeoutSeconds": 30,
                "maxResourceUnits": 10,
            },
        )

        assert invocation.status_code == 201
        assert invocation.json() == {
            "id": invocation.json()["id"],
            "runId": run["id"],
            "nodeId": "recon-1",
            "status": "completed",
            "output": {"summary": "API surface identified", "nextBranch": "verify"},
            "timeoutSeconds": 30,
            "resourceUnits": 4,
        }
        assert codex_cli.requests == [
            {
                "request": {
                    "runId": run["id"],
                    "nodeId": "recon-1",
                    "task": "Identify the API surface",
                    "input": {"target": "https://lab.example.test"},
                },
                "timeout_seconds": 30,
            }
        ]

        recorded = client.get(f"/api/runs/{run['id']}/ai-node-invocations")
        assert recorded.status_code == 200
        assert recorded.json() == [invocation.json()]

        audit = client.get(f"/api/runs/{run['id']}/audit")
        assert [event["eventType"] for event in audit.json()] == ["run.created", "ai-node.completed"]


def test_ai_node_timeout_is_recorded_in_the_execution_trail(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db", codex_cli=TimingOutCodexCli())

    with TestClient(app) as client:
        flow = client.post("/api/crystal-flows", json={"name": "Timeout assessment"}).json()
        run = client.post(f"/api/crystal-flows/{flow['id']}/runs").json()
        invocation = client.post(
            f"/api/runs/{run['id']}/ai-nodes",
            json={
                "nodeId": "recon-1",
                "task": "Identify the API surface",
                "input": {},
                "timeoutSeconds": 1,
                "maxResourceUnits": 10,
            },
        )

        audit = client.get(f"/api/runs/{run['id']}/audit")

    assert invocation.status_code == 201
    assert invocation.json()["status"] == "timeout"
    assert invocation.json()["resourceUnits"] == 0
    assert [event["eventType"] for event in audit.json()] == ["run.created", "ai-node.timeout"]


def test_run_routes_a_structured_agent_message_only_to_a_declared_branch(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")
    with TestClient(app) as client:
        flow = client.post("/api/crystal-flows", json={"name": "Adaptive flow"}).json()
        client.put(
            f"/api/crystal-flows/{flow['id']}",
            json={
                "nodes": [
                    {"id": "recon", "type": "recon-agent", "label": "Recon", "position": {"x": 0, "y": 0}, "config": {"branches": {"evidence": "verify"}}},
                    {"id": "verify", "type": "verification-step", "label": "Verify", "position": {"x": 200, "y": 0}, "config": {}},
                ],
                "edges": [{"id": "recon-verify", "source": "recon", "target": "verify"}],
            },
        )
        run = client.post(f"/api/crystal-flows/{flow['id']}/runs").json()
        routed = client.post(
            f"/api/runs/{run['id']}/node-results",
            json={"nodeId": "recon", "trigger": "evidence", "result": {"api": "/openapi.json"}},
        )

    assert routed.status_code == 201
    assert routed.json()["nodeStatus"] == "completed"
    assert routed.json()["nextNodeId"] == "verify"
    assert routed.json()["message"] == {"api": "/openapi.json"}


def test_bounded_loop_stops_after_its_declared_retry_limit(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")
    with TestClient(app) as client:
        flow = client.post("/api/crystal-flows", json={"name": "Bounded flow"}).json()
        client.put(f"/api/crystal-flows/{flow['id']}", json={
            "nodes": [
                {"id": "recon", "type": "recon-agent", "label": "Recon", "position": {"x": 0, "y": 0}, "config": {"branches": {"timeout": "retry"}, "boundedLoop": {"trigger": "timeout", "maxAttempts": 1}}},
                {"id": "retry", "type": "verification-step", "label": "Retry", "position": {"x": 200, "y": 0}, "config": {}},
            ],
            "edges": [{"id": "recon-retry", "source": "recon", "target": "retry"}],
        })
        run = client.post(f"/api/crystal-flows/{flow['id']}/runs").json()
        first = client.post(f"/api/runs/{run['id']}/node-results", json={"nodeId": "recon", "trigger": "timeout", "result": {}})
        second = client.post(f"/api/runs/{run['id']}/node-results", json={"nodeId": "recon", "trigger": "timeout", "result": {}})
        node_statuses = client.get(f"/api/runs/{run['id']}/node-statuses")

    assert first.json()["nodeStatus"] == "completed"
    assert first.json()["nextNodeId"] == "retry"
    assert second.json()["nodeStatus"] == "needs-human-review"
    assert second.json()["nextNodeId"] is None
    assert node_statuses.status_code == 200
    assert {item["nodeId"]: item["status"] for item in node_statuses.json()} == {
        "recon": "needs-human-review",
        "retry": "queued",
    }


def test_crystal_flow_rejects_an_invalid_bounded_loop_configuration(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")
    with TestClient(app) as client:
        flow = client.post("/api/crystal-flows", json={"name": "Invalid bounded flow"}).json()
        response = client.put(
            f"/api/crystal-flows/{flow['id']}",
            json={
                "nodes": [
                    {
                        "id": "recon",
                        "type": "recon-agent",
                        "label": "Recon",
                        "position": {"x": 0, "y": 0},
                        "config": {
                            "branches": {"timeout": "retry"},
                            "boundedLoop": {"trigger": "timeout", "maxAttempts": 0},
                        },
                    },
                    {
                        "id": "retry",
                        "type": "verification-step",
                        "label": "Retry",
                        "position": {"x": 200, "y": 0},
                        "config": {},
                    },
                ],
                "edges": [{"id": "recon-retry", "source": "recon", "target": "retry"}],
            },
    )

    assert response.status_code == 422
    assert "maxAttempts" in response.text


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


def test_required_action_resumes_only_after_owner_approval(tmp_path):
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
        ).json()
        decision = client.post(
            "/api/policy-decisions",
            json={
                "scopeId": scope["id"],
                "target": "https://lab.example.test",
                "action": "exploitation-attempt",
            },
        ).json()
        paused = client.post(f"/api/policy-decisions/{decision['id']}/resume")
        approval = client.post(f"/api/policy-decisions/{decision['id']}/approvals")
        resumed = client.post(f"/api/policy-decisions/{decision['id']}/resume")

    assert paused.status_code == 409
    assert approval.status_code == 201
    assert approval.json()["status"] == "approved"
    assert resumed.status_code == 200
    assert resumed.json()["status"] == "allow"
    assert resumed.json()["reason"] == "Owner Approval permits the action"


def test_reauthorization_uses_a_new_scope_version_without_overriding_a_policy_denial(tmp_path):
    app = create_app(database_path=tmp_path / "platform.db")
    now = datetime.now(UTC)
    initial_scope = {
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
        "authorizedLabEnvironment": False,
    }
    revised_scope = {**initial_scope, "unattendedExecution": True, "authorizedLabEnvironment": True}

    with TestClient(app) as client:
        scope = client.post("/api/scopes", json=initial_scope).json()
        denied = client.post(
            "/api/policy-decisions",
            json={
                "scopeId": scope["id"],
                "target": "https://lab.example.test",
                "action": "exploitation-attempt",
            },
        ).json()
        unrelated_scope = client.post("/api/scopes", json=revised_scope).json()
        rejected = client.post(
            f"/api/policy-decisions/{denied['id']}/reauthorizations",
            json={"scopeId": unrelated_scope["id"]},
        )
        version = client.post(f"/api/scopes/{scope['id']}/versions", json=revised_scope)
        reauthorized = client.post(
            f"/api/policy-decisions/{denied['id']}/reauthorizations",
            json={"scopeId": version.json()["id"]},
        )
        original_decisions = client.get(f"/api/scopes/{scope['id']}/policy-decisions")

    assert denied["status"] == "deny"
    assert rejected.status_code == 409
    assert version.status_code == 201
    assert version.json()["version"] == 2
    assert version.json()["previousScopeId"] == scope["id"]
    assert reauthorized.status_code == 201
    assert reauthorized.json()["status"] == "allow"
    assert original_decisions.json() == [denied]


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
