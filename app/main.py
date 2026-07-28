from __future__ import annotations

import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime
import json
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field, field_validator, model_validator

from app.policy import PolicyEngine, ScopePolicyInput
from app.session_adapter import (
    CodexCli,
    CodexCliError,
    CodexCliTimeout,
    SessionAdapter,
    SubprocessCodexCli,
)
from app.vm_runner import SshVmRunner, VmCommandResult, VmRunnerError

APPROVED_WORKFLOW_NODE_TYPES = {
    "recon-agent",
    "verification-step",
    "approval-gate",
    "custom-agent",
}


class CreateCrystalFlowRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)

    @field_validator("name")
    @classmethod
    def name_must_contain_visible_characters(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("name must contain visible characters")
        return value.strip()


class CrystalFlowResponse(BaseModel):
    id: str
    name: str
    version: int
    nodes: list[object]
    edges: list[object]


class WorkflowNodeRequest(BaseModel):
    id: str = Field(min_length=1)
    type: str = Field(min_length=1)
    label: str = Field(min_length=1)
    position: dict[str, float]
    config: dict[str, object]


class WorkflowEdgeRequest(BaseModel):
    id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    target: str = Field(min_length=1)


class SaveCrystalFlowRequest(BaseModel):
    nodes: list[WorkflowNodeRequest]
    edges: list[WorkflowEdgeRequest]

    @model_validator(mode="after")
    def graph_must_have_valid_edges(self) -> "SaveCrystalFlowRequest":
        node_ids = {node.id for node in self.nodes}
        if len(node_ids) != len(self.nodes):
            raise ValueError("Workflow Nodes must have unique IDs")
        edge_ids = {edge.id for edge in self.edges}
        if len(edge_ids) != len(self.edges):
            raise ValueError("Workflow Edges must have unique IDs")
        if any(node.type not in APPROVED_WORKFLOW_NODE_TYPES for node in self.nodes):
            raise ValueError("Workflow Nodes must use an approved node type")
        for edge in self.edges:
            if edge.source not in node_ids or edge.target not in node_ids:
                raise ValueError("Workflow Edges must connect existing Workflow Nodes")
            if edge.source == edge.target:
                raise ValueError("Workflow Edges cannot connect a node to itself")
        declared_edges = {(edge.source, edge.target) for edge in self.edges}
        for node in self.nodes:
            branches = node.config.get("branches", {})
            if not isinstance(branches, dict) or any(
                not isinstance(trigger, str) or not trigger or not isinstance(target, str) or not target
                for trigger, target in branches.items()
            ):
                raise ValueError("Workflow Node branches must map non-empty triggers to Node IDs")
            if any((node.id, target) not in declared_edges for target in branches.values()):
                raise ValueError("Workflow Node branches must use declared Workflow Edges")
            bounded_loop = node.config.get("boundedLoop")
            if bounded_loop is not None:
                if not isinstance(bounded_loop, dict):
                    raise ValueError("Bounded Loop configuration must be an object")
                trigger = bounded_loop.get("trigger")
                max_attempts = bounded_loop.get("maxAttempts")
                if (
                    not isinstance(trigger, str)
                    or not trigger
                    or trigger not in branches
                    or type(max_attempts) is not int
                    or max_attempts < 1
                ):
                    raise ValueError("Bounded Loop requires a declared trigger and maxAttempts of at least 1")
        return self


class RunResponse(BaseModel):
    id: str
    crystalFlowId: str
    status: str


class AuditEventResponse(BaseModel):
    eventType: str
    runId: str
    crystalFlowId: str


class ResourceLimitsRequest(BaseModel):
    maxRequestsPerSecond: int = Field(ge=1)
    maxConcurrentTasks: int = Field(ge=1)
    maxRuntimeSeconds: int = Field(ge=1)


class CreateScopeRequest(BaseModel):
    targets: list[str] = Field(min_length=1)
    workspace: str = Field(min_length=1)
    allowedActions: list[str] = Field(min_length=1)
    resourceLimits: ResourceLimitsRequest
    startsAt: datetime
    expiresAt: datetime
    unattendedExecution: bool
    authorizedLabEnvironment: bool

    @model_validator(mode="after")
    def scope_window_must_be_valid(self) -> "CreateScopeRequest":
        if self.startsAt.tzinfo is None or self.expiresAt.tzinfo is None:
            raise ValueError("Scope Window timestamps must include a timezone")
        if self.startsAt >= self.expiresAt:
            raise ValueError("Scope Window must expire after it starts")
        return self


class ScopeResponse(BaseModel):
    id: str


class CreatePolicyDecisionRequest(BaseModel):
    scopeId: str
    target: str = Field(min_length=1)
    action: str = Field(min_length=1)


class PolicyDecisionResponse(BaseModel):
    id: str
    scopeId: str
    target: str
    action: str
    status: str
    reason: str


class CreateVmTaskRequest(BaseModel):
    scopeId: str
    environment: str = Field(pattern="^(kali|debian)$")
    target: str = Field(min_length=1)
    action: str = Field(min_length=1)
    command: list[str] = Field(min_length=1)
    artifactReferences: list[str] = Field(default_factory=list)

    @field_validator("artifactReferences")
    @classmethod
    def artifact_references_must_stay_in_the_run_workspace(cls, references: list[str]) -> list[str]:
        if any(not reference or reference.startswith("/") or ".." in Path(reference).parts for reference in references):
            raise ValueError("artifact references must be relative to the Run Workspace")
        return references


class RunLogBundleResponse(BaseModel):
    id: str
    scopeId: str
    environment: str
    workspace: str
    status: str
    exitCode: int | None
    stdout: str
    stderr: str
    artifactReferences: list[str]


class CreateAiNodeRequest(BaseModel):
    nodeId: str = Field(min_length=1)
    task: str = Field(min_length=1)
    input: dict[str, object]
    timeoutSeconds: int = Field(ge=1)
    maxResourceUnits: int = Field(ge=1)


class AiNodeInvocationResponse(BaseModel):
    id: str
    runId: str
    nodeId: str
    status: str
    output: dict[str, object]
    timeoutSeconds: int
    resourceUnits: int


class CreateNodeResultRequest(BaseModel):
    nodeId: str = Field(min_length=1)
    trigger: str = Field(min_length=1)
    result: dict[str, object]


class NodeResultResponse(BaseModel):
    nodeStatus: str
    nextNodeId: str | None
    message: dict[str, object]


class NodeStatusResponse(BaseModel):
    nodeId: str
    status: str


def _connect(database_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    return connection


def _initialize_database(database_path: Path) -> None:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS crystal_flows (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                version INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS workflow_runs (
                id TEXT PRIMARY KEY,
                crystal_flow_id TEXT NOT NULL REFERENCES crystal_flows(id),
                status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS crystal_flow_versions (
                crystal_flow_id TEXT NOT NULL REFERENCES crystal_flows(id),
                version INTEGER NOT NULL,
                nodes_json TEXT NOT NULL,
                edges_json TEXT NOT NULL,
                PRIMARY KEY (crystal_flow_id, version)
            );

            CREATE TABLE IF NOT EXISTS execution_trail_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                run_id TEXT NOT NULL REFERENCES workflow_runs(id),
                crystal_flow_id TEXT NOT NULL REFERENCES crystal_flows(id)
            );

            CREATE TABLE IF NOT EXISTS scopes (
                id TEXT PRIMARY KEY,
                targets_json TEXT NOT NULL,
                workspace TEXT NOT NULL,
                allowed_actions_json TEXT NOT NULL,
                resource_limits_json TEXT NOT NULL,
                starts_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                unattended_execution INTEGER NOT NULL,
                authorized_lab_environment INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policy_decisions (
                id TEXT PRIMARY KEY,
                scope_id TEXT NOT NULL REFERENCES scopes(id),
                target TEXT NOT NULL,
                action TEXT NOT NULL,
                decision_status TEXT NOT NULL,
                reason TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS run_log_bundles (
                id TEXT PRIMARY KEY,
                scope_id TEXT NOT NULL REFERENCES scopes(id),
                environment TEXT NOT NULL,
                workspace TEXT NOT NULL,
                task_status TEXT NOT NULL,
                exit_code INTEGER,
                stdout TEXT NOT NULL,
                stderr TEXT NOT NULL,
                artifact_references_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ai_node_invocations (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES workflow_runs(id),
                node_id TEXT NOT NULL,
                invocation_status TEXT NOT NULL,
                output_json TEXT NOT NULL,
                timeout_seconds INTEGER NOT NULL,
                resource_units INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_messages (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES workflow_runs(id),
                source_node_id TEXT NOT NULL,
                target_node_id TEXT,
                trigger TEXT NOT NULL,
                message_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS node_statuses (
                run_id TEXT NOT NULL REFERENCES workflow_runs(id),
                node_id TEXT NOT NULL,
                status TEXT NOT NULL,
                PRIMARY KEY (run_id, node_id)
            );

            INSERT OR IGNORE INTO crystal_flow_versions (
                crystal_flow_id, version, nodes_json, edges_json
            )
            SELECT id, 1, '[]', '[]' FROM crystal_flows;
            """
        )


def create_app(
    database_path: Path | str = Path("data/platform.db"),
    vm_runner: object | None = None,
    codex_cli: CodexCli | None = None,
) -> FastAPI:
    resolved_database_path = Path(database_path)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        _initialize_database(resolved_database_path)
        yield

    app = FastAPI(title="Adaptive Security Orchestration Platform", lifespan=lifespan)
    policy_engine = PolicyEngine()
    configured_vm_runner = vm_runner or SshVmRunner.from_environment()
    session_adapter = SessionAdapter(codex_cli or SubprocessCodexCli())

    def current_crystal_flow(connection: sqlite3.Connection, crystal_flow_id: str) -> CrystalFlowResponse | None:
        flow = connection.execute(
            """
            SELECT flow.id, flow.name, version.version, version.nodes_json, version.edges_json
            FROM crystal_flows AS flow
            JOIN crystal_flow_versions AS version ON version.crystal_flow_id = flow.id
            WHERE flow.id = ?
            ORDER BY version.version DESC
            LIMIT 1
            """,
            (crystal_flow_id,),
        ).fetchone()
        if flow is None:
            return None
        return CrystalFlowResponse(
            id=flow["id"],
            name=flow["name"],
            version=flow["version"],
            nodes=json.loads(flow["nodes_json"]),
            edges=json.loads(flow["edges_json"]),
        )

    def scope_policy_input(scope: sqlite3.Row) -> ScopePolicyInput:
        return ScopePolicyInput(
            targets=tuple(json.loads(scope["targets_json"])),
            allowed_actions=tuple(json.loads(scope["allowed_actions_json"])),
            starts_at=datetime.fromisoformat(scope["starts_at"]),
            expires_at=datetime.fromisoformat(scope["expires_at"]),
            unattended_execution=bool(scope["unattended_execution"]),
            authorized_lab_environment=bool(scope["authorized_lab_environment"]),
        )

    def crystal_flow_version(
        connection: sqlite3.Connection, crystal_flow_id: str, version: int
    ) -> CrystalFlowResponse | None:
        flow = connection.execute(
            """
            SELECT flow.id, flow.name, version.version, version.nodes_json, version.edges_json
            FROM crystal_flows AS flow
            JOIN crystal_flow_versions AS version ON version.crystal_flow_id = flow.id
            WHERE flow.id = ? AND version.version = ?
            """,
            (crystal_flow_id, version),
        ).fetchone()
        if flow is None:
            return None
        return CrystalFlowResponse(
            id=flow["id"],
            name=flow["name"],
            version=flow["version"],
            nodes=json.loads(flow["nodes_json"]),
            edges=json.loads(flow["edges_json"]),
        )

    @app.post(
        "/api/crystal-flows",
        response_model=CrystalFlowResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_crystal_flow(request: CreateCrystalFlowRequest) -> CrystalFlowResponse:
        crystal_flow_id = uuid4().hex
        with _connect(resolved_database_path) as connection:
            connection.execute(
                "INSERT INTO crystal_flows (id, name, version) VALUES (?, ?, ?)",
                (crystal_flow_id, request.name, 1),
            )
            connection.execute(
                """
                INSERT INTO crystal_flow_versions (crystal_flow_id, version, nodes_json, edges_json)
                VALUES (?, ?, ?, ?)
                """,
                (crystal_flow_id, 1, "[]", "[]"),
            )
        return CrystalFlowResponse(
            id=crystal_flow_id,
            name=request.name,
            version=1,
            nodes=[],
            edges=[],
        )

    @app.get("/api/crystal-flows/{crystal_flow_id}", response_model=CrystalFlowResponse)
    def get_crystal_flow(crystal_flow_id: str) -> CrystalFlowResponse:
        with _connect(resolved_database_path) as connection:
            flow = current_crystal_flow(connection, crystal_flow_id)
        if flow is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Crystal Flow not found")
        return flow

    @app.get(
        "/api/crystal-flows/{crystal_flow_id}/versions/{version}",
        response_model=CrystalFlowResponse,
    )
    def get_crystal_flow_version(crystal_flow_id: str, version: int) -> CrystalFlowResponse:
        with _connect(resolved_database_path) as connection:
            flow = crystal_flow_version(connection, crystal_flow_id, version)
        if flow is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Crystal Flow version not found")
        return flow

    @app.get("/api/crystal-flows", response_model=list[CrystalFlowResponse])
    def list_crystal_flows() -> list[CrystalFlowResponse]:
        with _connect(resolved_database_path) as connection:
            flows = connection.execute(
                "SELECT id, name, version FROM crystal_flows ORDER BY rowid DESC"
            ).fetchall()
        return [
            current_crystal_flow(connection, flow["id"])
            for flow in flows
        ]

    @app.put("/api/crystal-flows/{crystal_flow_id}", response_model=CrystalFlowResponse)
    def save_crystal_flow(
        crystal_flow_id: str, request: SaveCrystalFlowRequest
    ) -> CrystalFlowResponse:
        with _connect(resolved_database_path) as connection:
            current_flow = current_crystal_flow(connection, crystal_flow_id)
            if current_flow is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Crystal Flow not found")
            next_version = current_flow.version + 1
            nodes = [node.model_dump() for node in request.nodes]
            edges = [edge.model_dump() for edge in request.edges]
            connection.execute(
                """
                INSERT INTO crystal_flow_versions (crystal_flow_id, version, nodes_json, edges_json)
                VALUES (?, ?, ?, ?)
                """,
                (crystal_flow_id, next_version, json.dumps(nodes), json.dumps(edges)),
            )
        return CrystalFlowResponse(
            id=current_flow.id,
            name=current_flow.name,
            version=next_version,
            nodes=nodes,
            edges=edges,
        )

    @app.post("/api/scopes", response_model=ScopeResponse, status_code=status.HTTP_201_CREATED)
    def create_scope(request: CreateScopeRequest) -> ScopeResponse:
        scope_id = uuid4().hex
        with _connect(resolved_database_path) as connection:
            connection.execute(
                """
                INSERT INTO scopes (
                    id, targets_json, workspace, allowed_actions_json, resource_limits_json,
                    starts_at, expires_at, unattended_execution, authorized_lab_environment
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scope_id,
                    json.dumps(request.targets),
                    request.workspace,
                    json.dumps(request.allowedActions),
                    request.resourceLimits.model_dump_json(),
                    request.startsAt.isoformat(),
                    request.expiresAt.isoformat(),
                    request.unattendedExecution,
                    request.authorizedLabEnvironment,
                ),
            )
        return ScopeResponse(id=scope_id)

    @app.post(
        "/api/policy-decisions",
        response_model=PolicyDecisionResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def evaluate_policy(request: CreatePolicyDecisionRequest) -> PolicyDecisionResponse:
        with _connect(resolved_database_path) as connection:
            scope = connection.execute("SELECT * FROM scopes WHERE id = ?", (request.scopeId,)).fetchone()
            if scope is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope not found")
            outcome = policy_engine.evaluate(
                scope_policy_input(scope),
                target=request.target,
                action=request.action,
            )
            decision_id = uuid4().hex
            connection.execute(
                """
                INSERT INTO policy_decisions (id, scope_id, target, action, decision_status, reason)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (decision_id, request.scopeId, request.target, request.action, outcome.status, outcome.reason),
            )
        return PolicyDecisionResponse(
            id=decision_id,
            scopeId=request.scopeId,
            target=request.target,
            action=request.action,
            status=outcome.status,
            reason=outcome.reason,
        )

    @app.get(
        "/api/scopes/{scope_id}/policy-decisions", response_model=list[PolicyDecisionResponse]
    )
    def list_policy_decisions(scope_id: str) -> list[PolicyDecisionResponse]:
        with _connect(resolved_database_path) as connection:
            decisions = connection.execute(
                """
                SELECT id, scope_id, target, action, decision_status, reason
                FROM policy_decisions
                WHERE scope_id = ?
                ORDER BY rowid
                """,
                (scope_id,),
            ).fetchall()
        return [
            PolicyDecisionResponse(
                id=decision["id"],
                scopeId=decision["scope_id"],
                target=decision["target"],
                action=decision["action"],
                status=decision["decision_status"],
                reason=decision["reason"],
            )
            for decision in decisions
        ]

    @app.post("/api/vm-tasks", response_model=RunLogBundleResponse, status_code=status.HTTP_201_CREATED)
    def run_vm_task(request: CreateVmTaskRequest) -> RunLogBundleResponse:
        with _connect(resolved_database_path) as connection:
            scope = connection.execute("SELECT * FROM scopes WHERE id = ?", (request.scopeId,)).fetchone()
            if scope is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope not found")
            outcome = policy_engine.evaluate(
                scope_policy_input(scope), target=request.target, action=request.action
            )
            workspace = scope["workspace"]
            if outcome.status != "allow":
                command_result = VmCommandResult(exit_code=0, stdout="", stderr=outcome.reason)
                task_status = "blocked"
                exit_code: int | None = None
            else:
                try:
                    limits = json.loads(scope["resource_limits_json"])
                    command_result = configured_vm_runner.execute(
                        environment=request.environment,
                        workspace=workspace,
                        command=request.command,
                        timeout_seconds=limits["maxRuntimeSeconds"],
                    )
                    task_status = "completed" if command_result.exit_code == 0 else "failed"
                    exit_code = command_result.exit_code
                except VmRunnerError as error:
                    command_result = VmCommandResult(exit_code=1, stdout="", stderr=str(error))
                    task_status = "failed"
                    exit_code = 1
            log_bundle_id = uuid4().hex
            connection.execute(
                """
                INSERT INTO run_log_bundles (
                    id, scope_id, environment, workspace, task_status, exit_code, stdout, stderr,
                    artifact_references_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    log_bundle_id,
                    request.scopeId,
                    request.environment,
                    workspace,
                    task_status,
                    exit_code,
                    command_result.stdout,
                    command_result.stderr,
                    json.dumps(request.artifactReferences),
                ),
            )
        return RunLogBundleResponse(
            id=log_bundle_id,
            scopeId=request.scopeId,
            environment=request.environment,
            workspace=workspace,
            status=task_status,
            exitCode=exit_code,
            stdout=command_result.stdout,
            stderr=command_result.stderr,
            artifactReferences=request.artifactReferences,
        )

    @app.get("/api/scopes/{scope_id}/run-log-bundles", response_model=list[RunLogBundleResponse])
    def list_run_log_bundles(scope_id: str) -> list[RunLogBundleResponse]:
        with _connect(resolved_database_path) as connection:
            bundles = connection.execute(
                """
                SELECT id, scope_id, environment, workspace, task_status, exit_code, stdout, stderr,
                       artifact_references_json
                FROM run_log_bundles
                WHERE scope_id = ?
                ORDER BY rowid
                """,
                (scope_id,),
            ).fetchall()
        return [
            RunLogBundleResponse(
                id=bundle["id"],
                scopeId=bundle["scope_id"],
                environment=bundle["environment"],
                workspace=bundle["workspace"],
                status=bundle["task_status"],
                exitCode=bundle["exit_code"],
                stdout=bundle["stdout"],
                stderr=bundle["stderr"],
                artifactReferences=json.loads(bundle["artifact_references_json"]),
            )
            for bundle in bundles
        ]

    @app.post(
        "/api/runs/{run_id}/ai-nodes",
        response_model=AiNodeInvocationResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def execute_ai_node(run_id: str, request: CreateAiNodeRequest) -> AiNodeInvocationResponse:
        with _connect(resolved_database_path) as connection:
            run = connection.execute(
                "SELECT crystal_flow_id FROM workflow_runs WHERE id = ?", (run_id,)
            ).fetchone()
            if run is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workflow run not found")
            session_request = {
                "runId": run_id,
                "nodeId": request.nodeId,
                "task": request.task,
                "input": request.input,
            }
            try:
                result = session_adapter.execute(session_request, request.timeoutSeconds)
                invocation_status = (
                    "completed" if result.resource_units <= request.maxResourceUnits else "resource-exceeded"
                )
                output = result.output
                resource_units = result.resource_units
            except CodexCliTimeout as error:
                invocation_status = "timeout"
                output = {"reason": str(error)}
                resource_units = 0
            except CodexCliError as error:
                invocation_status = "failed"
                output = {"reason": str(error)}
                resource_units = 0
            invocation_id = uuid4().hex
            connection.execute(
                """
                INSERT INTO ai_node_invocations (
                    id, run_id, node_id, invocation_status, output_json, timeout_seconds, resource_units
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    invocation_id,
                    run_id,
                    request.nodeId,
                    invocation_status,
                    json.dumps(output),
                    request.timeoutSeconds,
                    resource_units,
                ),
            )
            connection.execute(
                """
                INSERT INTO execution_trail_events (event_type, run_id, crystal_flow_id)
                VALUES (?, ?, ?)
                """,
                (f"ai-node.{invocation_status}", run_id, run["crystal_flow_id"]),
            )
        return AiNodeInvocationResponse(
            id=invocation_id,
            runId=run_id,
            nodeId=request.nodeId,
            status=invocation_status,
            output=output,
            timeoutSeconds=request.timeoutSeconds,
            resourceUnits=resource_units,
        )

    @app.get("/api/runs/{run_id}/ai-node-invocations", response_model=list[AiNodeInvocationResponse])
    def list_ai_node_invocations(run_id: str) -> list[AiNodeInvocationResponse]:
        with _connect(resolved_database_path) as connection:
            invocations = connection.execute(
                """
                SELECT id, run_id, node_id, invocation_status, output_json, timeout_seconds, resource_units
                FROM ai_node_invocations
                WHERE run_id = ?
                ORDER BY rowid
                """,
                (run_id,),
            ).fetchall()
        return [
            AiNodeInvocationResponse(
                id=invocation["id"],
                runId=invocation["run_id"],
                nodeId=invocation["node_id"],
                status=invocation["invocation_status"],
                output=json.loads(invocation["output_json"]),
                timeoutSeconds=invocation["timeout_seconds"],
                resourceUnits=invocation["resource_units"],
            )
            for invocation in invocations
        ]

    @app.post("/api/runs/{run_id}/node-results", response_model=NodeResultResponse, status_code=status.HTTP_201_CREATED)
    def route_node_result(run_id: str, request: CreateNodeResultRequest) -> NodeResultResponse:
        with _connect(resolved_database_path) as connection:
            run = connection.execute("SELECT crystal_flow_id FROM workflow_runs WHERE id = ?", (run_id,)).fetchone()
            if run is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workflow run not found")
            flow = current_crystal_flow(connection, run["crystal_flow_id"])
            assert flow is not None
            nodes = {node["id"]: node for node in flow.nodes}
            source = nodes.get(request.nodeId)
            if source is None:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Workflow Node is not in this Crystal Flow")
            branches = source.get("config", {}).get("branches", {})
            next_node_id = branches.get(request.trigger) if isinstance(branches, dict) else None
            node_status = "completed"
            bounded_loop = source.get("config", {}).get("boundedLoop", {})
            if isinstance(bounded_loop, dict) and bounded_loop.get("trigger") == request.trigger:
                attempts = connection.execute(
                    "SELECT COUNT(*) AS count FROM agent_messages WHERE run_id = ? AND source_node_id = ? AND trigger = ?",
                    (run_id, request.nodeId, request.trigger),
                ).fetchone()["count"]
                if attempts >= bounded_loop.get("maxAttempts", 0):
                    next_node_id = None
                    node_status = "needs-human-review"
            valid_edges = {(edge["source"], edge["target"]) for edge in flow.edges}
            if next_node_id is not None and (request.nodeId, next_node_id) not in valid_edges:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Branch is not declared by a Workflow Edge")
            connection.execute(
                "INSERT INTO agent_messages (id, run_id, source_node_id, target_node_id, trigger, message_json) VALUES (?, ?, ?, ?, ?, ?)",
                (uuid4().hex, run_id, request.nodeId, next_node_id, request.trigger, json.dumps(request.result)),
            )
            connection.execute(
                "INSERT INTO execution_trail_events (event_type, run_id, crystal_flow_id) VALUES (?, ?, ?)",
                (f"node.{node_status}", run_id, run["crystal_flow_id"]),
            )
            connection.execute(
                "INSERT OR REPLACE INTO node_statuses (run_id, node_id, status) VALUES (?, ?, ?)",
                (run_id, request.nodeId, node_status),
            )
            if next_node_id is not None:
                connection.execute(
                    "INSERT OR REPLACE INTO node_statuses (run_id, node_id, status) VALUES (?, ?, ?)",
                    (run_id, next_node_id, "queued"),
                )
        return NodeResultResponse(nodeStatus=node_status, nextNodeId=next_node_id, message=request.result)

    @app.get("/api/runs/{run_id}/node-statuses", response_model=list[NodeStatusResponse])
    def list_node_statuses(run_id: str) -> list[NodeStatusResponse]:
        with _connect(resolved_database_path) as connection:
            rows = connection.execute("SELECT node_id, status FROM node_statuses WHERE run_id = ? ORDER BY rowid", (run_id,)).fetchall()
        return [NodeStatusResponse(nodeId=row["node_id"], status=row["status"]) for row in rows]

    @app.post(
        "/api/crystal-flows/{crystal_flow_id}/runs",
        response_model=RunResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_run(crystal_flow_id: str) -> RunResponse:
        run_id = uuid4().hex
        with _connect(resolved_database_path) as connection:
            flow_exists = connection.execute(
                "SELECT 1 FROM crystal_flows WHERE id = ?", (crystal_flow_id,)
            ).fetchone()
            if flow_exists is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Crystal Flow not found")
            connection.execute(
                "INSERT INTO workflow_runs (id, crystal_flow_id, status) VALUES (?, ?, ?)",
                (run_id, crystal_flow_id, "created"),
            )
            connection.execute(
                """
                INSERT INTO execution_trail_events (event_type, run_id, crystal_flow_id)
                VALUES (?, ?, ?)
                """,
                ("run.created", run_id, crystal_flow_id),
            )
        return RunResponse(id=run_id, crystalFlowId=crystal_flow_id, status="created")

    @app.get("/api/runs/{run_id}/audit", response_model=list[AuditEventResponse])
    def get_run_audit(run_id: str) -> list[AuditEventResponse]:
        with _connect(resolved_database_path) as connection:
            events = connection.execute(
                """
                SELECT event_type, run_id, crystal_flow_id
                FROM execution_trail_events
                WHERE run_id = ?
                ORDER BY id
                """,
                (run_id,),
            ).fetchall()
        if not events:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run audit not found")
        return [
            AuditEventResponse(
                eventType=event["event_type"],
                runId=event["run_id"],
                crystalFlowId=event["crystal_flow_id"],
            )
            for event in events
        ]

    return app


app = create_app()
