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

            INSERT OR IGNORE INTO crystal_flow_versions (
                crystal_flow_id, version, nodes_json, edges_json
            )
            SELECT id, 1, '[]', '[]' FROM crystal_flows;
            """
        )


def create_app(database_path: Path | str = Path("data/platform.db")) -> FastAPI:
    resolved_database_path = Path(database_path)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        _initialize_database(resolved_database_path)
        yield

    app = FastAPI(title="Adaptive Security Orchestration Platform", lifespan=lifespan)
    policy_engine = PolicyEngine()

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
                ScopePolicyInput(
                    targets=tuple(json.loads(scope["targets_json"])),
                    allowed_actions=tuple(json.loads(scope["allowed_actions_json"])),
                    starts_at=datetime.fromisoformat(scope["starts_at"]),
                    expires_at=datetime.fromisoformat(scope["expires_at"]),
                    unattended_execution=bool(scope["unattended_execution"]),
                    authorized_lab_environment=bool(scope["authorized_lab_environment"]),
                ),
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
