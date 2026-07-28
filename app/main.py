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
            flow = connection.execute(
                "SELECT id, name, version FROM crystal_flows WHERE id = ?", (crystal_flow_id,)
            ).fetchone()
        if flow is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Crystal Flow not found")
        return CrystalFlowResponse(
            id=flow["id"], name=flow["name"], version=flow["version"], nodes=[], edges=[]
        )

    @app.get("/api/crystal-flows", response_model=list[CrystalFlowResponse])
    def list_crystal_flows() -> list[CrystalFlowResponse]:
        with _connect(resolved_database_path) as connection:
            flows = connection.execute(
                "SELECT id, name, version FROM crystal_flows ORDER BY rowid DESC"
            ).fetchall()
        return [
            CrystalFlowResponse(
                id=flow["id"], name=flow["name"], version=flow["version"], nodes=[], edges=[]
            )
            for flow in flows
        ]

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
