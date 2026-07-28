from __future__ import annotations

import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field, field_validator


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
            """
        )


def create_app(database_path: Path | str = Path("data/platform.db")) -> FastAPI:
    resolved_database_path = Path(database_path)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        _initialize_database(resolved_database_path)
        yield

    app = FastAPI(title="Adaptive Security Orchestration Platform", lifespan=lifespan)

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
