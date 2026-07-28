from __future__ import annotations

import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime
import json
from pathlib import Path
from typing import Literal
from uuid import uuid4

from cryptography.fernet import Fernet
from fastapi import BackgroundTasks, FastAPI, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.policy import PolicyEngine, PolicyOutcome, ScopePolicyInput
from app.session_adapter import (
    CodexCli,
    CodexCliError,
    CodexCliTimeout,
    SessionAdapter,
    SubprocessCodexCli,
)
from app.vm_runner import SshVmRunner, VmCommandResult, VmRunnerError

APPROVED_WORKFLOW_NODE_TYPES = {
    "start-node",
    "recon-agent",
    "verification-step",
    "approval-gate",
    "custom-agent",
    "resolve-worker",
    "exit-node",
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
    version: int
    previousScopeId: str | None


class CreatePolicyDecisionRequest(BaseModel):
    scopeId: str
    target: str = Field(min_length=1)
    action: str = Field(min_length=1)


class CreateReauthorizationRequest(BaseModel):
    scopeId: str


class PolicyDecisionResponse(BaseModel):
    id: str
    scopeId: str
    target: str
    action: str
    status: str
    reason: str


class ApprovalResponse(BaseModel):
    id: str
    policyDecisionId: str
    status: str


class ActionResumeResponse(BaseModel):
    status: str
    reason: str


class ConfigureCodexSessionRequest(BaseModel):
    command: str = Field(max_length=1024)


class CodexSessionResponse(BaseModel):
    configured: bool
    command: str


class PluginManifestRequest(BaseModel):
    capabilities: list[str] = Field(min_length=1)
    permissions: list[str] = Field(min_length=1)
    inputSchema: dict[str, object]
    outputSchema: dict[str, object]


class CreatePluginRequest(BaseModel):
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    builtin: bool
    checksum: str | None = Field(default=None, pattern="^[A-Fa-f0-9]{64}$")
    ownerApproved: bool = False
    manifest: PluginManifestRequest

    @model_validator(mode="after")
    def external_plugins_require_mvp_trust_checks(self) -> "CreatePluginRequest":
        if not self.builtin and (self.checksum is None or not self.ownerApproved):
            raise ValueError("External Plugins require an approved checksum and Owner approval")
        return self


class PluginResponse(BaseModel):
    id: str
    name: str
    version: str
    builtin: bool
    checksum: str | None
    status: str
    integrityVerified: bool
    manifest: PluginManifestRequest


class ExecutionLimitsRequest(BaseModel):
    maxAttempts: int = Field(ge=1)
    maxRuntimeSeconds: int = Field(ge=1)


class CreateCustomAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    objective: str = Field(min_length=1)
    instructions: str = Field(min_length=1)
    inputs: dict[str, object]
    capabilities: list[str] = Field(min_length=1)
    permissions: list[str] = Field(min_length=1)
    executionLimits: ExecutionLimitsRequest
    pluginId: str


class CustomAgentResponse(BaseModel):
    id: str
    name: str
    objective: str
    instructions: str
    inputs: dict[str, object]
    capabilities: list[str]
    permissions: list[str]
    executionLimits: ExecutionLimitsRequest
    pluginId: str


class EnablePluginRequest(BaseModel):
    pluginId: str


class ReferenceCatalogResponse(BaseModel):
    agentIds: list[str]
    benchmarkFlowId: str


class ExecutionEnvironmentRequest(BaseModel):
    sshTarget: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._@:-]*$",
    )


class ExecutionEnvironmentResponse(BaseModel):
    environment: Literal["kali", "debian"]
    sshTarget: str


class PrepareWorkspaceRequest(BaseModel):
    workspace: str = Field(min_length=2, max_length=1024)

    @field_validator("workspace")
    @classmethod
    def workspace_must_be_an_absolute_bounded_path(cls, value: str) -> str:
        workspace = Path(value)
        if not workspace.is_absolute() or ".." in workspace.parts or value == "/":
            raise ValueError("workspace must be an absolute, non-root path without traversal")
        return value


class PrepareWorkspaceResponse(BaseModel):
    environment: Literal["kali", "debian"]
    workspace: str
    status: str


class ConfigurationAuditEventResponse(BaseModel):
    eventType: str
    subject: str
    detail: dict[str, object]
    createdAt: datetime


class BenchmarkFlowResponse(BaseModel):
    crystalFlowId: str
    demonstrates: list[str]


class CreateEvidenceRecordRequest(BaseModel):
    runId: str
    target: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    sha256: str = Field(pattern="^[A-Fa-f0-9]{64}$")
    storage: Literal["host", "vm-resident"]
    vmResidentPath: str | None = None
    availability: Literal["available", "unavailable"]
    sensitive: bool

    @model_validator(mode="after")
    def vm_resident_evidence_requires_a_safe_path(self) -> "CreateEvidenceRecordRequest":
        if self.storage == "vm-resident":
            if not self.vmResidentPath or self.vmResidentPath.startswith("/") or ".." in Path(self.vmResidentPath).parts:
                raise ValueError("VM-Resident Artifacts require a relative Run Workspace path")
        return self


class EvidenceRecordResponse(BaseModel):
    id: str
    runId: str
    target: str
    summary: str
    sha256: str
    storage: str
    vmResidentPath: str | None
    availability: str
    sensitive: bool


class EvidenceAccessEventResponse(BaseModel):
    eventType: str


class CreateFindingRequest(BaseModel):
    title: str = Field(min_length=1)
    target: str = Field(min_length=1)
    runId: str
    evidenceRecordIds: list[str] = Field(min_length=1)
    runLogBundleIds: list[str] = Field(default_factory=list)
    policyDecisionIds: list[str] = Field(default_factory=list)

    @field_validator("evidenceRecordIds", "runLogBundleIds", "policyDecisionIds")
    @classmethod
    def provenance_references_must_be_unique(cls, references: list[str]) -> list[str]:
        if len(set(references)) != len(references):
            raise ValueError("Finding provenance references must be unique")
        return references


class AgentMessageProvenanceResponse(BaseModel):
    sourceNodeId: str
    trigger: str
    message: dict[str, object]


class ToolCallProvenanceResponse(BaseModel):
    id: str
    scopeId: str
    environment: str
    workspace: str
    status: str
    exitCode: int | None
    stdout: str
    stderr: str
    artifactReferences: list[str]


class FindingProvenanceResponse(BaseModel):
    nodeIds: list[str]
    agentMessages: list[AgentMessageProvenanceResponse]
    toolCalls: list[ToolCallProvenanceResponse]
    policyDecisions: list[PolicyDecisionResponse]
    evidenceArtifacts: list[EvidenceRecordResponse]


class FindingResponse(BaseModel):
    id: str
    title: str
    target: str
    runId: str
    provenance: FindingProvenanceResponse


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
    model: str | None = Field(
        default=None,
        min_length=1,
        max_length=120,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    reasoningEffort: Literal["low", "medium", "high", "xhigh"] = "medium"
    timeoutSeconds: int = Field(ge=1)
    maxResourceUnits: int = Field(ge=1)


class AiNodeInvocationResponse(BaseModel):
    id: str
    runId: str
    nodeId: str
    status: str
    output: dict[str, object]
    model: str | None
    reasoningEffort: str
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


class AgentMessageResponse(BaseModel):
    sourceNodeId: str
    targetNodeId: str | None
    trigger: str
    message: dict[str, object]


def _connect(database_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    return connection


def _evidence_cipher(database_path: Path) -> Fernet:
    key_path = database_path.with_suffix(".evidence.key")
    if key_path.exists():
        key = key_path.read_bytes()
    else:
        key = Fernet.generate_key()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(key)
        key_path.chmod(0o600)
    return Fernet(key)


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
                status TEXT NOT NULL,
                stop_requested INTEGER NOT NULL DEFAULT 0
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

            CREATE TABLE IF NOT EXISTS scope_versions (
                scope_id TEXT PRIMARY KEY REFERENCES scopes(id),
                root_scope_id TEXT NOT NULL REFERENCES scopes(id),
                version INTEGER NOT NULL,
                previous_scope_id TEXT REFERENCES scopes(id)
            );

            CREATE TABLE IF NOT EXISTS policy_decisions (
                id TEXT PRIMARY KEY,
                scope_id TEXT NOT NULL REFERENCES scopes(id),
                target TEXT NOT NULL,
                action TEXT NOT NULL,
                decision_status TEXT NOT NULL,
                reason TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policy_reauthorizations (
                id TEXT PRIMARY KEY,
                original_decision_id TEXT NOT NULL REFERENCES policy_decisions(id),
                reauthorized_decision_id TEXT NOT NULL REFERENCES policy_decisions(id),
                scope_id TEXT NOT NULL REFERENCES scopes(id)
            );

            CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY,
                policy_decision_id TEXT NOT NULL UNIQUE REFERENCES policy_decisions(id),
                approval_status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS action_resumptions (
                id TEXT PRIMARY KEY,
                policy_decision_id TEXT NOT NULL REFERENCES policy_decisions(id),
                approval_id TEXT REFERENCES approvals(id),
                resume_status TEXT NOT NULL,
                reason TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS plugins (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                builtin INTEGER NOT NULL,
                checksum TEXT,
                plugin_status TEXT NOT NULL,
                integrity_verified INTEGER NOT NULL,
                manifest_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS custom_agents (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                objective TEXT NOT NULL,
                instructions TEXT NOT NULL,
                inputs_json TEXT NOT NULL,
                capabilities_json TEXT NOT NULL,
                permissions_json TEXT NOT NULL,
                execution_limits_json TEXT NOT NULL,
                plugin_id TEXT NOT NULL REFERENCES plugins(id)
            );

            CREATE TABLE IF NOT EXISTS crystal_flow_plugins (
                crystal_flow_id TEXT NOT NULL REFERENCES crystal_flows(id),
                version INTEGER NOT NULL,
                plugin_id TEXT NOT NULL REFERENCES plugins(id),
                PRIMARY KEY (crystal_flow_id, version, plugin_id)
            );

            CREATE TABLE IF NOT EXISTS reference_agents (
                custom_agent_id TEXT PRIMARY KEY REFERENCES custom_agents(id),
                plugin_id TEXT NOT NULL REFERENCES plugins(id),
                catalog_position INTEGER NOT NULL UNIQUE
            );

            CREATE TABLE IF NOT EXISTS benchmark_flows (
                crystal_flow_id TEXT PRIMARY KEY REFERENCES crystal_flows(id),
                demonstrates_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS execution_environments (
                environment TEXT PRIMARY KEY,
                ssh_target TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS configuration_audit_events (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                subject TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runtime_settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evidence_records (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES workflow_runs(id),
                target TEXT NOT NULL,
                encrypted_summary TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                storage TEXT NOT NULL,
                vm_resident_path TEXT,
                availability TEXT NOT NULL,
                sensitive INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evidence_access_events (
                id TEXT PRIMARY KEY,
                evidence_record_id TEXT NOT NULL REFERENCES evidence_records(id),
                event_type TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                target TEXT NOT NULL,
                run_id TEXT NOT NULL REFERENCES workflow_runs(id)
            );

            CREATE TABLE IF NOT EXISTS finding_evidence_records (
                finding_id TEXT NOT NULL REFERENCES findings(id),
                evidence_record_id TEXT NOT NULL REFERENCES evidence_records(id),
                PRIMARY KEY (finding_id, evidence_record_id)
            );

            CREATE TABLE IF NOT EXISTS finding_run_log_bundles (
                finding_id TEXT NOT NULL REFERENCES findings(id),
                run_log_bundle_id TEXT NOT NULL REFERENCES run_log_bundles(id),
                PRIMARY KEY (finding_id, run_log_bundle_id)
            );

            CREATE TABLE IF NOT EXISTS finding_policy_decisions (
                finding_id TEXT NOT NULL REFERENCES findings(id),
                policy_decision_id TEXT NOT NULL REFERENCES policy_decisions(id),
                PRIMARY KEY (finding_id, policy_decision_id)
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
                model TEXT,
                reasoning_effort TEXT NOT NULL DEFAULT 'medium',
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
        run_columns = {row["name"] for row in connection.execute("PRAGMA table_info(workflow_runs)").fetchall()}
        if "stop_requested" not in run_columns:
            connection.execute("ALTER TABLE workflow_runs ADD COLUMN stop_requested INTEGER NOT NULL DEFAULT 0")
        invocation_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(ai_node_invocations)").fetchall()
        }
        if "model" not in invocation_columns:
            connection.execute("ALTER TABLE ai_node_invocations ADD COLUMN model TEXT")
        if "reasoning_effort" not in invocation_columns:
            connection.execute(
                "ALTER TABLE ai_node_invocations "
                "ADD COLUMN reasoning_effort TEXT NOT NULL DEFAULT 'medium'"
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
        with _connect(resolved_database_path) as connection:
            session_setting = connection.execute(
                "SELECT setting_value FROM runtime_settings WHERE setting_key = ?",
                ("codex_session_command",),
            ).fetchone()
        if session_setting is not None and session_setting["setting_value"].strip():
            session_adapter.configure_command(session_setting["setting_value"])
        configure_environment = getattr(configured_vm_runner, "configure", None)
        if callable(configure_environment):
            with _connect(resolved_database_path) as connection:
                environments = connection.execute(
                    "SELECT environment, ssh_target FROM execution_environments"
                ).fetchall()
            for environment in environments:
                configure_environment(environment["environment"], environment["ssh_target"])
        yield

    app = FastAPI(title="Adaptive Security Orchestration Platform", lifespan=lifespan)
    policy_engine = PolicyEngine()
    configured_vm_runner = vm_runner or SshVmRunner.from_environment()
    session_adapter = SessionAdapter(codex_cli or SubprocessCodexCli())
    evidence_cipher = _evidence_cipher(resolved_database_path)

    def evidence_record_response(
        evidence_record: sqlite3.Row, *, reveal_sensitive_summary: bool = False
    ) -> EvidenceRecordResponse:
        summary = evidence_cipher.decrypt(evidence_record["encrypted_summary"].encode()).decode()
        if evidence_record["sensitive"] and not reveal_sensitive_summary:
            summary = "[Sensitive Evidence masked]"
        return EvidenceRecordResponse(
            id=evidence_record["id"],
            runId=evidence_record["run_id"],
            target=evidence_record["target"],
            summary=summary,
            sha256=evidence_record["sha256"],
            storage=evidence_record["storage"],
            vmResidentPath=evidence_record["vm_resident_path"],
            availability=evidence_record["availability"],
            sensitive=bool(evidence_record["sensitive"]),
        )

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

    def plugin_response(plugin: sqlite3.Row) -> PluginResponse:
        return PluginResponse(
            id=plugin["id"],
            name=plugin["name"],
            version=plugin["version"],
            builtin=bool(plugin["builtin"]),
            checksum=plugin["checksum"],
            status=plugin["plugin_status"],
            integrityVerified=bool(plugin["integrity_verified"]),
            manifest=PluginManifestRequest.model_validate(json.loads(plugin["manifest_json"])),
        )

    def custom_agent_response(agent: sqlite3.Row) -> CustomAgentResponse:
        return CustomAgentResponse(
            id=agent["id"],
            name=agent["name"],
            objective=agent["objective"],
            instructions=agent["instructions"],
            inputs=json.loads(agent["inputs_json"]),
            capabilities=json.loads(agent["capabilities_json"]),
            permissions=json.loads(agent["permissions_json"]),
            executionLimits=ExecutionLimitsRequest.model_validate(json.loads(agent["execution_limits_json"])),
            pluginId=agent["plugin_id"],
        )

    def flow_plugin_ids(connection: sqlite3.Connection, crystal_flow_id: str, version: int) -> set[str]:
        return {
            row["plugin_id"]
            for row in connection.execute(
                "SELECT plugin_id FROM crystal_flow_plugins WHERE crystal_flow_id = ? AND version = ?",
                (crystal_flow_id, version),
            ).fetchall()
        }

    def provision_reference_catalog(connection: sqlite3.Connection) -> ReferenceCatalogResponse:
        reference_agents = [
            ("Recon Agent", "reconnaissance", "network.read"),
            ("Repository/Code Review Agent", "repository-review", "filesystem.read"),
            ("Web/API Review Agent", "api-review", "network.read"),
            ("Verification Agent", "verification", "network.read"),
            ("Reporting Agent", "reporting", "evidence.read"),
        ]
        custom_agent_ids: list[str] = []
        plugin_ids: list[str] = []
        for position, (name, capability, permission) in enumerate(reference_agents, start=1):
            reference_agent = connection.execute(
                """
                SELECT reference.custom_agent_id, reference.plugin_id
                FROM reference_agents AS reference
                WHERE reference.catalog_position = ?
                """,
                (position,),
            ).fetchone()
            if reference_agent is None:
                plugin_id = uuid4().hex
                custom_agent_id = uuid4().hex
                manifest = PluginManifestRequest(
                    capabilities=[capability],
                    permissions=[permission],
                    inputSchema={"type": "object"},
                    outputSchema={"type": "object"},
                )
                connection.execute(
                    """
                    INSERT INTO plugins (
                        id, name, version, builtin, checksum, plugin_status, integrity_verified, manifest_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (plugin_id, f"Built-in {name}", "1.0.0", True, None, "approved", True, manifest.model_dump_json()),
                )
                connection.execute(
                    """
                    INSERT INTO custom_agents (
                        id, name, objective, instructions, inputs_json, capabilities_json,
                        permissions_json, execution_limits_json, plugin_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        custom_agent_id,
                        name,
                        f"Perform bounded {capability} work in the active Crystal Flow.",
                        "Use only the approved Plugin capability and return structured evidence.",
                        "{}",
                        json.dumps([capability]),
                        json.dumps([permission]),
                        ExecutionLimitsRequest(maxAttempts=2, maxRuntimeSeconds=120).model_dump_json(),
                        plugin_id,
                    ),
                )
                connection.execute(
                    "INSERT INTO reference_agents (custom_agent_id, plugin_id, catalog_position) VALUES (?, ?, ?)",
                    (custom_agent_id, plugin_id, position),
                )
            else:
                custom_agent_id = reference_agent["custom_agent_id"]
                plugin_id = reference_agent["plugin_id"]
            custom_agent_ids.append(custom_agent_id)
            plugin_ids.append(plugin_id)

        benchmark = connection.execute("SELECT crystal_flow_id FROM benchmark_flows LIMIT 1").fetchone()
        if benchmark is None:
            benchmark_flow_id = uuid4().hex
            nodes = [
                {"id": "recon", "type": "custom-agent", "label": "Recon Agent", "position": {"x": 0, "y": 0}, "config": {"customAgentId": custom_agent_ids[0], "branches": {"evidence": "repository", "timeout": "verification"}}},
                {"id": "repository", "type": "custom-agent", "label": "Repository/Code Review Agent", "position": {"x": 220, "y": -100}, "config": {"customAgentId": custom_agent_ids[1], "branches": {"review-complete": "web-api"}}},
                {"id": "web-api", "type": "custom-agent", "label": "Web/API Review Agent", "position": {"x": 440, "y": -100}, "config": {"customAgentId": custom_agent_ids[2], "branches": {"evidence": "approval"}}},
                {"id": "approval", "type": "approval-gate", "label": "Owner Approval", "position": {"x": 660, "y": -100}, "config": {"branches": {"approved": "verification"}}},
                {"id": "verification", "type": "custom-agent", "label": "Verification Agent", "position": {"x": 440, "y": 120}, "config": {"customAgentId": custom_agent_ids[3], "branches": {"verified": "reporting", "timeout": "repository"}, "boundedLoop": {"trigger": "timeout", "maxAttempts": 1}}},
                {"id": "reporting", "type": "custom-agent", "label": "Reporting Agent", "position": {"x": 680, "y": 120}, "config": {"customAgentId": custom_agent_ids[4]}},
            ]
            edges = [
                {"id": "recon-repository", "source": "recon", "target": "repository"},
                {"id": "recon-verification", "source": "recon", "target": "verification"},
                {"id": "repository-web-api", "source": "repository", "target": "web-api"},
                {"id": "web-api-approval", "source": "web-api", "target": "approval"},
                {"id": "approval-verification", "source": "approval", "target": "verification"},
                {"id": "verification-repository", "source": "verification", "target": "repository"},
                {"id": "verification-reporting", "source": "verification", "target": "reporting"},
            ]
            demonstrates = ["policy-blocking", "approval", "bounded-adaptation", "timeout-handling", "evidence-reconstruction"]
            connection.execute("INSERT INTO crystal_flows (id, name, version) VALUES (?, ?, ?)", (benchmark_flow_id, "Lab safety benchmark", 1))
            connection.execute(
                "INSERT INTO crystal_flow_versions (crystal_flow_id, version, nodes_json, edges_json) VALUES (?, ?, ?, ?)",
                (benchmark_flow_id, 1, json.dumps(nodes), json.dumps(edges)),
            )
            connection.executemany(
                "INSERT INTO crystal_flow_plugins (crystal_flow_id, version, plugin_id) VALUES (?, ?, ?)",
                [(benchmark_flow_id, 1, plugin_id) for plugin_id in plugin_ids],
            )
            connection.execute(
                "INSERT INTO benchmark_flows (crystal_flow_id, demonstrates_json) VALUES (?, ?)",
                (benchmark_flow_id, json.dumps(demonstrates)),
            )
        else:
            benchmark_flow_id = benchmark["crystal_flow_id"]
        return ReferenceCatalogResponse(agentIds=custom_agent_ids, benchmarkFlowId=benchmark_flow_id)

    def finding_response(connection: sqlite3.Connection, finding: sqlite3.Row) -> FindingResponse:
        node_ids = [
            row["node_id"]
            for row in connection.execute(
                "SELECT node_id FROM node_statuses WHERE run_id = ? ORDER BY rowid", (finding["run_id"],)
            ).fetchall()
        ]
        agent_messages = [
            AgentMessageProvenanceResponse(
                sourceNodeId=row["source_node_id"],
                trigger=row["trigger"],
                message=json.loads(row["message_json"]),
            )
            for row in connection.execute(
                """
                SELECT source_node_id, trigger, message_json
                FROM agent_messages
                WHERE run_id = ?
                ORDER BY rowid
                """,
                (finding["run_id"],),
            ).fetchall()
        ]
        evidence_artifacts = [
            evidence_record_response(row)
            for row in connection.execute(
                """
                SELECT evidence.* FROM evidence_records AS evidence
                JOIN finding_evidence_records AS finding_evidence
                    ON finding_evidence.evidence_record_id = evidence.id
                WHERE finding_evidence.finding_id = ?
                ORDER BY evidence.rowid
                """,
                (finding["id"],),
            ).fetchall()
        ]
        tool_calls = [
            ToolCallProvenanceResponse(
                id=row["id"],
                scopeId=row["scope_id"],
                environment=row["environment"],
                workspace=row["workspace"],
                status=row["task_status"],
                exitCode=row["exit_code"],
                stdout=row["stdout"],
                stderr=row["stderr"],
                artifactReferences=json.loads(row["artifact_references_json"]),
            )
            for row in connection.execute(
                """
                SELECT run_log_bundle.* FROM run_log_bundles AS run_log_bundle
                JOIN finding_run_log_bundles AS finding_tool_call
                    ON finding_tool_call.run_log_bundle_id = run_log_bundle.id
                WHERE finding_tool_call.finding_id = ?
                ORDER BY run_log_bundle.rowid
                """,
                (finding["id"],),
            ).fetchall()
        ]
        policy_decisions = [
            PolicyDecisionResponse(
                id=row["id"],
                scopeId=row["scope_id"],
                target=row["target"],
                action=row["action"],
                status=row["decision_status"],
                reason=row["reason"],
            )
            for row in connection.execute(
                """
                SELECT policy_decision.* FROM policy_decisions AS policy_decision
                JOIN finding_policy_decisions AS finding_policy_decision
                    ON finding_policy_decision.policy_decision_id = policy_decision.id
                WHERE finding_policy_decision.finding_id = ?
                ORDER BY policy_decision.rowid
                """,
                (finding["id"],),
            ).fetchall()
        ]
        return FindingResponse(
            id=finding["id"],
            title=finding["title"],
            target=finding["target"],
            runId=finding["run_id"],
            provenance=FindingProvenanceResponse(
                nodeIds=node_ids,
                agentMessages=agent_messages,
                toolCalls=tool_calls,
                policyDecisions=policy_decisions,
                evidenceArtifacts=evidence_artifacts,
            ),
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

    def set_run_status(run_id: str, run_status: str) -> None:
        with _connect(resolved_database_path) as connection:
            connection.execute("UPDATE workflow_runs SET status = ? WHERE id = ?", (run_status, run_id))

    def run_stop_requested(run_id: str) -> bool:
        with _connect(resolved_database_path) as connection:
            run = connection.execute(
                "SELECT stop_requested FROM workflow_runs WHERE id = ?", (run_id,)
            ).fetchone()
        return bool(run and run["stop_requested"])

    def record_run_event(run_id: str, event_type: str, crystal_flow_id: str) -> None:
        with _connect(resolved_database_path) as connection:
            connection.execute(
                "INSERT INTO execution_trail_events (event_type, run_id, crystal_flow_id) VALUES (?, ?, ?)",
                (event_type, run_id, crystal_flow_id),
            )

    def set_node_status(run_id: str, node_id: str, node_status: str) -> None:
        with _connect(resolved_database_path) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO node_statuses (run_id, node_id, status) VALUES (?, ?, ?)",
                (run_id, node_id, node_status),
            )

    def record_agent_message(
        run_id: str,
        source_node_id: str,
        target_node_id: str | None,
        trigger: str,
        message: dict[str, object],
    ) -> None:
        with _connect(resolved_database_path) as connection:
            connection.execute(
                """
                INSERT INTO agent_messages (
                    id, run_id, source_node_id, target_node_id, trigger, message_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (uuid4().hex, run_id, source_node_id, target_node_id, trigger, json.dumps(message)),
            )

    def orchestrate_run(run_id: str) -> None:
        """Execute a bounded Crystal Flow in the background after Start Run."""
        try:
            with _connect(resolved_database_path) as connection:
                run = connection.execute(
                    "SELECT crystal_flow_id FROM workflow_runs WHERE id = ?", (run_id,)
                ).fetchone()
                if run is None:
                    return
                flow = current_crystal_flow(connection, run["crystal_flow_id"])
            if flow is None:
                set_run_status(run_id, "failed")
                return

            flow_nodes = {node["id"]: node for node in flow.nodes}
            if not flow.nodes:
                # A blank flow is still a valid draft, but there is nothing to execute.
                return
            outgoing = {}
            for edge in flow.edges:
                outgoing.setdefault(edge["source"], []).append(edge["target"])
            start_nodes = [node for node in flow.nodes if node["type"] == "start-node"]
            if not start_nodes:
                # Runs without an explicit Start node remain available for the
                # existing manual node-result API; they are not auto-executed.
                return
            current_node_id = start_nodes[0]["id"]
            previous_output: dict[str, object] = {}
            attempts: dict[tuple[str, str], int] = {}
            set_run_status(run_id, "running")
            record_run_event(run_id, "run.started", flow.id)

            for _ in range(100):
                if run_stop_requested(run_id):
                    return
                if current_node_id is None:
                    set_run_status(run_id, "completed")
                    record_run_event(run_id, "run.completed", flow.id)
                    return
                node = flow_nodes.get(current_node_id)
                if node is None:
                    set_run_status(run_id, "failed")
                    record_run_event(run_id, "run.failed.node-not-found", flow.id)
                    return
                node_id = node["id"]
                config = node.get("config", {})
                set_node_status(run_id, node_id, "running")
                record_run_event(run_id, f"node.started.{node_id}", flow.id)

                node_type = node["type"]
                if node_type == "exit-node":
                    set_node_status(run_id, node_id, "completed")
                    record_run_event(run_id, f"node.completed.{node_id}", flow.id)
                    set_run_status(run_id, "completed")
                    record_run_event(run_id, "run.completed", flow.id)
                    return

                if node_type == "approval-gate":
                    set_node_status(run_id, node_id, "needs-human-review")
                    record_agent_message(run_id, node_id, None, "approval-required", {"reason": "Owner Approval is required before continuing"})
                    record_run_event(run_id, "node.needs-human-review", flow.id)
                    set_run_status(run_id, "waiting-for-approval")
                    return

                trigger = "started" if node_type == "start-node" else "completed"
                output: dict[str, object]
                node_status = "completed"
                action = config.get("action") if isinstance(config, dict) else None
                if not isinstance(action, str):
                    action = "verification"
                scope_id = config.get("scopeId") if isinstance(config, dict) else None
                target = config.get("target") if isinstance(config, dict) else None

                if node_type == "start-node":
                    output = {"status": "started", "nodeId": node_id}
                elif not isinstance(scope_id, str) or not isinstance(target, str):
                    node_status = "failed"
                    output = {"reason": "Node requires a Scope ID and target"}
                else:
                    with _connect(resolved_database_path) as connection:
                        scope = connection.execute("SELECT * FROM scopes WHERE id = ?", (scope_id,)).fetchone()
                    if scope is None:
                        node_status = "failed"
                        output = {"reason": "Scope not found"}
                    else:
                        outcome = policy_engine.evaluate(scope_policy_input(scope), target=target, action=action)
                        with _connect(resolved_database_path) as connection:
                            decision_id = uuid4().hex
                            connection.execute(
                                "INSERT INTO policy_decisions (id, scope_id, target, action, decision_status, reason) VALUES (?, ?, ?, ?, ?, ?)",
                                (decision_id, scope_id, target, action, outcome.status, outcome.reason),
                            )
                        record_run_event(run_id, f"policy.{outcome.status}.{node_id}", flow.id)
                        if outcome.status != "allow":
                            node_status = "needs-human-review" if outcome.status == "approval-required" else "blocked"
                            output = {"reason": outcome.reason, "policyDecisionId": decision_id}
                            set_node_status(run_id, node_id, node_status)
                            record_agent_message(run_id, node_id, None, "policy-blocked", output)
                            set_run_status(run_id, "waiting-for-approval" if outcome.status == "approval-required" else "blocked")
                            record_run_event(run_id, f"node.{node_status}", flow.id)
                            return

                        if action == "file-analysis":
                            command = config.get("command") if isinstance(config.get("command"), list) else ["file", target]
                            try:
                                limits = json.loads(scope["resource_limits_json"])
                                result = configured_vm_runner.execute(
                                    environment=str(config.get("environment", "kali")),
                                    workspace=scope["workspace"],
                                    command=[str(item) for item in command],
                                    timeout_seconds=limits["maxRuntimeSeconds"],
                                )
                                node_status = "completed" if result.exit_code == 0 else "failed"
                                output = {"stdout": result.stdout, "stderr": result.stderr, "exitCode": result.exit_code}
                            except VmRunnerError as error:
                                node_status = "failed"
                                output = {"reason": str(error)}
                        else:
                            model = config.get("model") if isinstance(config.get("model"), str) else None
                            effort = config.get("reasoningEffort") if isinstance(config.get("reasoningEffort"), str) else "medium"
                            timeout_seconds = int(config.get("timeoutSeconds", 120))
                            max_resource_units = int(config.get("maxResourceUnits", 50))
                            session_request = {
                                "runId": run_id,
                                "nodeId": node_id,
                                "task": str(config.get("task", f"Execute the {node.get('label', node_type)} step for the authorized target.")),
                                "input": {"target": target, "previous": previous_output},
                                "model": model,
                                "reasoningEffort": effort,
                            }
                            try:
                                result = session_adapter.execute(session_request, timeout_seconds)
                                node_status = "completed" if result.resource_units <= max_resource_units else "resource-exceeded"
                                output = result.output
                                with _connect(resolved_database_path) as connection:
                                    connection.execute(
                                        "INSERT INTO ai_node_invocations (id, run_id, node_id, invocation_status, output_json, model, reasoning_effort, timeout_seconds, resource_units) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                        (uuid4().hex, run_id, node_id, node_status, json.dumps(output), model, effort, timeout_seconds, result.resource_units),
                                    )
                            except CodexCliTimeout as error:
                                node_status = "timeout"
                                output = {"reason": str(error)}
                            except CodexCliError as error:
                                node_status = "failed"
                                output = {"reason": str(error)}

                if run_stop_requested(run_id):
                    set_node_status(run_id, node_id, "stopped")
                    record_agent_message(run_id, node_id, None, "execution-stopped", output)
                    return
                set_node_status(run_id, node_id, node_status)
                record_run_event(run_id, f"node.{node_status}", flow.id)
                previous_output = output
                if node_status != "completed":
                    set_run_status(run_id, node_status)
                    record_run_event(run_id, "run.failed", flow.id)
                    record_agent_message(run_id, node_id, None, "execution-stopped", output)
                    return
                branches = config.get("branches", {}) if isinstance(config, dict) else {}
                next_node_id = branches.get(trigger) if isinstance(branches, dict) else None
                if next_node_id is None and node_type not in {"start-node", "exit-node"}:
                    next_node_id = (outgoing.get(node_id) or [None])[0]
                if next_node_id is not None:
                    loop_key = (node_id, trigger)
                    attempts[loop_key] = attempts.get(loop_key, 0) + 1
                    bounded_loop = config.get("boundedLoop") if isinstance(config, dict) else None
                    if isinstance(bounded_loop, dict) and bounded_loop.get("trigger") == trigger and attempts[loop_key] > int(bounded_loop.get("maxAttempts", 1)):
                        set_node_status(run_id, node_id, "needs-human-review")
                        set_run_status(run_id, "waiting-for-approval")
                        record_run_event(run_id, "run.bounded-loop-limit", flow.id)
                        return
                    record_agent_message(run_id, node_id, next_node_id, trigger, output)
                    set_node_status(run_id, next_node_id, "queued")
                else:
                    set_run_status(run_id, "completed" if node_status == "completed" else node_status)
                    record_run_event(run_id, "run.completed" if node_status == "completed" else "run.failed", flow.id)
                    return
                current_node_id = next_node_id

            set_run_status(run_id, "failed")
            record_run_event(run_id, "run.step-limit-exceeded", flow.id)
        except Exception as error:
            set_run_status(run_id, "failed")
            with _connect(resolved_database_path) as connection:
                run = connection.execute("SELECT crystal_flow_id FROM workflow_runs WHERE id = ?", (run_id,)).fetchone()
            if run is not None:
                record_run_event(run_id, f"run.failed.{type(error).__name__}", run["crystal_flow_id"])

    def save_scope_version(
        connection: sqlite3.Connection,
        request: CreateScopeRequest,
        *,
        root_scope_id: str,
        version: int,
        previous_scope_id: str | None,
        scope_id: str | None = None,
    ) -> ScopeResponse:
        scope_id = scope_id or uuid4().hex
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
        connection.execute(
            "INSERT INTO scope_versions (scope_id, root_scope_id, version, previous_scope_id) VALUES (?, ?, ?, ?)",
            (scope_id, root_scope_id, version, previous_scope_id),
        )
        return ScopeResponse(id=scope_id, version=version, previousScopeId=previous_scope_id)

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

    @app.post("/api/plugins", response_model=PluginResponse, status_code=status.HTTP_201_CREATED)
    def admit_plugin(request: CreatePluginRequest) -> PluginResponse:
        plugin_id = uuid4().hex
        with _connect(resolved_database_path) as connection:
            connection.execute(
                """
                INSERT INTO plugins (
                    id, name, version, builtin, checksum, plugin_status, integrity_verified, manifest_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plugin_id,
                    request.name,
                    request.version,
                    request.builtin,
                    request.checksum,
                    "approved",
                    True,
                    request.manifest.model_dump_json(),
                ),
            )
        return PluginResponse(
            id=plugin_id,
            name=request.name,
            version=request.version,
            builtin=request.builtin,
            checksum=request.checksum,
            status="approved",
            integrityVerified=True,
            manifest=request.manifest,
        )

    @app.get("/api/plugins", response_model=list[PluginResponse])
    def list_plugins() -> list[PluginResponse]:
        with _connect(resolved_database_path) as connection:
            plugins = connection.execute("SELECT * FROM plugins ORDER BY rowid").fetchall()
        return [plugin_response(plugin) for plugin in plugins]

    @app.post("/api/custom-agents", response_model=CustomAgentResponse, status_code=status.HTTP_201_CREATED)
    def create_custom_agent(request: CreateCustomAgentRequest) -> CustomAgentResponse:
        agent_id = uuid4().hex
        with _connect(resolved_database_path) as connection:
            plugin = connection.execute("SELECT * FROM plugins WHERE id = ?", (request.pluginId,)).fetchone()
            if plugin is None or plugin["plugin_status"] != "approved":
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Custom Agent requires an Approved Plugin")
            manifest = PluginManifestRequest.model_validate(json.loads(plugin["manifest_json"]))
            if not set(request.capabilities).issubset(manifest.capabilities):
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Custom Agent capabilities must be declared by its Plugin")
            if not set(request.permissions).issubset(manifest.permissions):
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Custom Agent permissions must be declared by its Plugin")
            connection.execute(
                """
                INSERT INTO custom_agents (
                    id, name, objective, instructions, inputs_json, capabilities_json,
                    permissions_json, execution_limits_json, plugin_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    agent_id,
                    request.name,
                    request.objective,
                    request.instructions,
                    json.dumps(request.inputs),
                    json.dumps(request.capabilities),
                    json.dumps(request.permissions),
                    request.executionLimits.model_dump_json(),
                    request.pluginId,
                ),
            )
        return CustomAgentResponse(id=agent_id, **request.model_dump())

    @app.get("/api/custom-agents", response_model=list[CustomAgentResponse])
    def list_custom_agents() -> list[CustomAgentResponse]:
        with _connect(resolved_database_path) as connection:
            agents = connection.execute("SELECT * FROM custom_agents ORDER BY rowid").fetchall()
        return [custom_agent_response(agent) for agent in agents]

    @app.post("/api/reference-catalog", response_model=ReferenceCatalogResponse, status_code=status.HTTP_201_CREATED)
    def provision_reference_agents() -> ReferenceCatalogResponse:
        with _connect(resolved_database_path) as connection:
            return provision_reference_catalog(connection)

    @app.get("/api/reference-agents", response_model=list[CustomAgentResponse])
    def list_reference_agents() -> list[CustomAgentResponse]:
        with _connect(resolved_database_path) as connection:
            agents = connection.execute(
                """
                SELECT agent.* FROM custom_agents AS agent
                JOIN reference_agents AS reference ON reference.custom_agent_id = agent.id
                ORDER BY reference.catalog_position
                """
            ).fetchall()
        return [custom_agent_response(agent) for agent in agents]

    @app.get(
        "/api/execution-environments",
        response_model=list[ExecutionEnvironmentResponse],
    )
    def list_execution_environments() -> list[ExecutionEnvironmentResponse]:
        with _connect(resolved_database_path) as connection:
            stored = {
                row["environment"]: row["ssh_target"]
                for row in connection.execute(
                    "SELECT environment, ssh_target FROM execution_environments"
                ).fetchall()
            }
        configured_targets = getattr(configured_vm_runner, "configured_targets", None)
        if callable(configured_targets):
            for environment, ssh_target in configured_targets().items():
                if ssh_target:
                    stored.setdefault(environment, ssh_target)
        return [
            ExecutionEnvironmentResponse(environment=environment, sshTarget=stored.get(environment, ""))
            for environment in ("kali", "debian")
            if stored.get(environment)
        ]

    @app.put(
        "/api/execution-environments/{environment}",
        response_model=ExecutionEnvironmentResponse,
    )
    def configure_execution_environment(
        environment: Literal["kali", "debian"],
        request: ExecutionEnvironmentRequest,
    ) -> ExecutionEnvironmentResponse:
        with _connect(resolved_database_path) as connection:
            connection.execute(
                """
                INSERT INTO execution_environments (environment, ssh_target)
                VALUES (?, ?)
                ON CONFLICT(environment) DO UPDATE SET ssh_target = excluded.ssh_target
                """,
                (environment, request.sshTarget),
            )
            connection.execute(
                """
                INSERT INTO configuration_audit_events (
                    id, event_type, subject, detail_json, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    uuid4().hex,
                    "execution-environment.configured",
                    environment,
                    json.dumps({"sshTarget": request.sshTarget}),
                    datetime.now().astimezone().isoformat(),
                ),
            )
        configure_environment = getattr(configured_vm_runner, "configure", None)
        if callable(configure_environment):
            configure_environment(environment, request.sshTarget)
        return ExecutionEnvironmentResponse(
            environment=environment,
            sshTarget=request.sshTarget,
        )

    @app.post(
        "/api/execution-environments/{environment}/workspaces",
        response_model=PrepareWorkspaceResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def prepare_execution_workspace(
        environment: Literal["kali", "debian"],
        request: PrepareWorkspaceRequest,
    ) -> PrepareWorkspaceResponse:
        prepare_workspace = getattr(configured_vm_runner, "prepare_workspace", None)
        if not callable(prepare_workspace):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Execution environment cannot prepare a Workspace",
            )
        try:
            prepare_workspace(environment=environment, workspace=request.workspace)
        except VmRunnerError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(error),
            ) from error
        with _connect(resolved_database_path) as connection:
            connection.execute(
                """
                INSERT INTO configuration_audit_events (
                    id, event_type, subject, detail_json, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    uuid4().hex,
                    "execution-workspace.prepared",
                    environment,
                    json.dumps({"workspace": request.workspace}),
                    datetime.now().astimezone().isoformat(),
                ),
            )
        return PrepareWorkspaceResponse(
            environment=environment,
            workspace=request.workspace,
            status="ready",
        )

    @app.get("/api/codex-session", response_model=CodexSessionResponse)
    def get_codex_session() -> CodexSessionResponse:
        with _connect(resolved_database_path) as connection:
            setting = connection.execute(
                "SELECT setting_value FROM runtime_settings WHERE setting_key = ?",
                ("codex_session_command",),
            ).fetchone()
        command = setting["setting_value"] if setting else ""
        return CodexSessionResponse(configured=bool(command.strip()), command=command)

    @app.put("/api/codex-session", response_model=CodexSessionResponse)
    def configure_codex_session(request: ConfigureCodexSessionRequest) -> CodexSessionResponse:
        command = request.command.strip()
        if not command:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Codex Session command is required",
            )
        try:
            session_adapter.configure_command(command)
        except CodexCliError as error:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
        with _connect(resolved_database_path) as connection:
            connection.execute(
                "INSERT INTO runtime_settings (setting_key, setting_value) VALUES (?, ?) "
                "ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value",
                ("codex_session_command", command),
            )
            connection.execute(
                "INSERT INTO configuration_audit_events (id, event_type, subject, detail_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    uuid4().hex,
                    "codex-session.configured",
                    "codex-session",
                    json.dumps({"configured": True}),
                    datetime.now().astimezone().isoformat(),
                ),
            )
        return CodexSessionResponse(configured=True, command=command)

    @app.get(
        "/api/configuration-audit",
        response_model=list[ConfigurationAuditEventResponse],
    )
    def list_configuration_audit_events() -> list[ConfigurationAuditEventResponse]:
        with _connect(resolved_database_path) as connection:
            events = connection.execute(
                """
                SELECT event_type, subject, detail_json, created_at
                FROM configuration_audit_events
                ORDER BY rowid DESC
                """
            ).fetchall()
        return [
            ConfigurationAuditEventResponse(
                eventType=event["event_type"],
                subject=event["subject"],
                detail=json.loads(event["detail_json"]),
                createdAt=datetime.fromisoformat(event["created_at"]),
            )
            for event in events
        ]

    @app.get("/api/benchmark-flows", response_model=list[BenchmarkFlowResponse])
    def list_benchmark_flows() -> list[BenchmarkFlowResponse]:
        with _connect(resolved_database_path) as connection:
            benchmarks = connection.execute(
                "SELECT crystal_flow_id, demonstrates_json FROM benchmark_flows ORDER BY rowid"
            ).fetchall()
        return [
            BenchmarkFlowResponse(
                crystalFlowId=benchmark["crystal_flow_id"],
                demonstrates=json.loads(benchmark["demonstrates_json"]),
            )
            for benchmark in benchmarks
        ]

    @app.post("/api/crystal-flows/{crystal_flow_id}/plugins", response_model=CrystalFlowResponse)
    def enable_plugin_in_crystal_flow(
        crystal_flow_id: str, request: EnablePluginRequest
    ) -> CrystalFlowResponse:
        with _connect(resolved_database_path) as connection:
            flow = current_crystal_flow(connection, crystal_flow_id)
            if flow is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Crystal Flow not found")
            plugin = connection.execute("SELECT * FROM plugins WHERE id = ?", (request.pluginId,)).fetchone()
            if plugin is None or plugin["plugin_status"] != "approved":
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Crystal Flow requires an Approved Plugin")
            if request.pluginId in flow_plugin_ids(connection, crystal_flow_id, flow.version):
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Plugin is already enabled in this Crystal Flow")
            next_version = flow.version + 1
            connection.execute(
                """
                INSERT INTO crystal_flow_versions (crystal_flow_id, version, nodes_json, edges_json)
                VALUES (?, ?, ?, ?)
                """,
                (crystal_flow_id, next_version, json.dumps(flow.nodes), json.dumps(flow.edges)),
            )
            connection.execute(
                """
                INSERT INTO crystal_flow_plugins (crystal_flow_id, version, plugin_id)
                SELECT crystal_flow_id, ?, plugin_id
                FROM crystal_flow_plugins
                WHERE crystal_flow_id = ? AND version = ?
                """,
                (next_version, crystal_flow_id, flow.version),
            )
            connection.execute(
                "INSERT INTO crystal_flow_plugins (crystal_flow_id, version, plugin_id) VALUES (?, ?, ?)",
                (crystal_flow_id, next_version, request.pluginId),
            )
        return CrystalFlowResponse(
            id=flow.id,
            name=flow.name,
            version=next_version,
            nodes=flow.nodes,
            edges=flow.edges,
        )

    @app.get("/api/crystal-flows/{crystal_flow_id}/plugins", response_model=list[PluginResponse])
    def list_enabled_crystal_flow_plugins(crystal_flow_id: str) -> list[PluginResponse]:
        with _connect(resolved_database_path) as connection:
            flow = current_crystal_flow(connection, crystal_flow_id)
            if flow is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Crystal Flow not found")
            plugins = connection.execute(
                """
                SELECT plugin.* FROM plugins AS plugin
                JOIN crystal_flow_plugins AS enabled_plugin ON enabled_plugin.plugin_id = plugin.id
                WHERE enabled_plugin.crystal_flow_id = ? AND enabled_plugin.version = ?
                ORDER BY plugin.rowid
                """,
                (crystal_flow_id, flow.version),
            ).fetchall()
        return [plugin_response(plugin) for plugin in plugins]

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

    @app.delete(
        "/api/crystal-flows/{crystal_flow_id}",
        status_code=status.HTTP_204_NO_CONTENT,
    )
    def delete_crystal_flow(crystal_flow_id: str) -> None:
        with _connect(resolved_database_path) as connection:
            flow = connection.execute(
                "SELECT 1 FROM crystal_flows WHERE id = ?", (crystal_flow_id,)
            ).fetchone()
            if flow is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Crystal Flow not found",
                )

            run_ids = [
                row["id"]
                for row in connection.execute(
                    "SELECT id FROM workflow_runs WHERE crystal_flow_id = ?",
                    (crystal_flow_id,),
                ).fetchall()
            ]
            if run_ids:
                run_placeholders = ",".join("?" for _ in run_ids)
                finding_ids = [
                    row["id"]
                    for row in connection.execute(
                        f"SELECT id FROM findings WHERE run_id IN ({run_placeholders})",
                        run_ids,
                    ).fetchall()
                ]
                evidence_ids = [
                    row["id"]
                    for row in connection.execute(
                        f"SELECT id FROM evidence_records WHERE run_id IN ({run_placeholders})",
                        run_ids,
                    ).fetchall()
                ]

                if finding_ids:
                    finding_placeholders = ",".join("?" for _ in finding_ids)
                    connection.execute(
                        f"DELETE FROM finding_evidence_records WHERE finding_id IN ({finding_placeholders})",
                        finding_ids,
                    )
                    connection.execute(
                        f"DELETE FROM finding_run_log_bundles WHERE finding_id IN ({finding_placeholders})",
                        finding_ids,
                    )
                    connection.execute(
                        f"DELETE FROM finding_policy_decisions WHERE finding_id IN ({finding_placeholders})",
                        finding_ids,
                    )
                    connection.execute(
                        f"DELETE FROM findings WHERE id IN ({finding_placeholders})",
                        finding_ids,
                    )
                if evidence_ids:
                    evidence_placeholders = ",".join("?" for _ in evidence_ids)
                    connection.execute(
                        f"DELETE FROM evidence_access_events WHERE evidence_record_id IN ({evidence_placeholders})",
                        evidence_ids,
                    )
                    connection.execute(
                        f"DELETE FROM evidence_records WHERE id IN ({evidence_placeholders})",
                        evidence_ids,
                    )

                for table in ("ai_node_invocations", "agent_messages", "node_statuses"):
                    connection.execute(
                        f"DELETE FROM {table} WHERE run_id IN ({run_placeholders})",
                        run_ids,
                    )
                connection.execute(
                    f"DELETE FROM execution_trail_events WHERE run_id IN ({run_placeholders})",
                    run_ids,
                )
                connection.execute(
                    f"DELETE FROM workflow_runs WHERE id IN ({run_placeholders})",
                    run_ids,
                )

            connection.execute(
                "DELETE FROM benchmark_flows WHERE crystal_flow_id = ?",
                (crystal_flow_id,),
            )
            connection.execute(
                "DELETE FROM crystal_flow_plugins WHERE crystal_flow_id = ?",
                (crystal_flow_id,),
            )
            connection.execute(
                "DELETE FROM crystal_flow_versions WHERE crystal_flow_id = ?",
                (crystal_flow_id,),
            )
            connection.execute(
                "DELETE FROM crystal_flows WHERE id = ?", (crystal_flow_id,)
            )

    @app.put("/api/crystal-flows/{crystal_flow_id}", response_model=CrystalFlowResponse)
    def save_crystal_flow(
        crystal_flow_id: str, request: SaveCrystalFlowRequest
    ) -> CrystalFlowResponse:
        with _connect(resolved_database_path) as connection:
            current_flow = current_crystal_flow(connection, crystal_flow_id)
            if current_flow is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Crystal Flow not found")
            enabled_plugin_ids = flow_plugin_ids(connection, crystal_flow_id, current_flow.version)
            for node in request.nodes:
                if node.type != "custom-agent":
                    continue
                custom_agent_id = node.config.get("customAgentId")
                if not isinstance(custom_agent_id, str) or not custom_agent_id:
                    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Custom Agent Nodes require a Custom Agent")
                custom_agent = connection.execute(
                    "SELECT plugin_id FROM custom_agents WHERE id = ?", (custom_agent_id,)
                ).fetchone()
                if custom_agent is None:
                    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Custom Agent is not approved")
                if custom_agent["plugin_id"] not in enabled_plugin_ids:
                    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Custom Agent Plugin is not enabled in this Crystal Flow")
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
            connection.execute(
                """
                INSERT INTO crystal_flow_plugins (crystal_flow_id, version, plugin_id)
                SELECT crystal_flow_id, ?, plugin_id
                FROM crystal_flow_plugins
                WHERE crystal_flow_id = ? AND version = ?
                """,
                (next_version, crystal_flow_id, current_flow.version),
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
        with _connect(resolved_database_path) as connection:
            scope_id = uuid4().hex
            return save_scope_version(
                connection,
                request,
                root_scope_id=scope_id,
                version=1,
                previous_scope_id=None,
                scope_id=scope_id,
            )

    @app.post("/api/scopes/{scope_id}/versions", response_model=ScopeResponse, status_code=status.HTTP_201_CREATED)
    def create_scope_version(scope_id: str, request: CreateScopeRequest) -> ScopeResponse:
        with _connect(resolved_database_path) as connection:
            existing_scope = connection.execute("SELECT 1 FROM scopes WHERE id = ?", (scope_id,)).fetchone()
            if existing_scope is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope not found")
            current_version = connection.execute(
                "SELECT root_scope_id, version FROM scope_versions WHERE scope_id = ?", (scope_id,)
            ).fetchone()
            if current_version is None:
                current_version = {"root_scope_id": scope_id, "version": 1}
                connection.execute(
                    "INSERT INTO scope_versions (scope_id, root_scope_id, version, previous_scope_id) VALUES (?, ?, ?, ?)",
                    (scope_id, scope_id, 1, None),
                )
            return save_scope_version(
                connection,
                request,
                root_scope_id=current_version["root_scope_id"],
                version=current_version["version"] + 1,
                previous_scope_id=scope_id,
            )

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

    @app.post(
        "/api/policy-decisions/{policy_decision_id}/reauthorizations",
        response_model=PolicyDecisionResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def reauthorize_policy_denial(
        policy_decision_id: str, request: CreateReauthorizationRequest
    ) -> PolicyDecisionResponse:
        with _connect(resolved_database_path) as connection:
            original_decision = connection.execute(
                "SELECT * FROM policy_decisions WHERE id = ?", (policy_decision_id,)
            ).fetchone()
            if original_decision is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy Decision not found")
            if original_decision["decision_status"] != "deny":
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only a Policy Denial can be reauthorized")
            scope = connection.execute("SELECT * FROM scopes WHERE id = ?", (request.scopeId,)).fetchone()
            if scope is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope not found")
            original_scope_version = connection.execute(
                "SELECT root_scope_id, version FROM scope_versions WHERE scope_id = ?",
                (original_decision["scope_id"],),
            ).fetchone()
            reauthorization_scope_version = connection.execute(
                "SELECT root_scope_id, version FROM scope_versions WHERE scope_id = ?", (request.scopeId,)
            ).fetchone()
            if (
                original_scope_version is None
                or reauthorization_scope_version is None
                or original_scope_version["root_scope_id"] != reauthorization_scope_version["root_scope_id"]
                or reauthorization_scope_version["version"] <= original_scope_version["version"]
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Reauthorization requires a newer version of the original Scope",
                )
            outcome = policy_engine.evaluate(
                scope_policy_input(scope), target=original_decision["target"], action=original_decision["action"]
            )
            reauthorized_decision_id = uuid4().hex
            connection.execute(
                """
                INSERT INTO policy_decisions (id, scope_id, target, action, decision_status, reason)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    reauthorized_decision_id,
                    request.scopeId,
                    original_decision["target"],
                    original_decision["action"],
                    outcome.status,
                    outcome.reason,
                ),
            )
            connection.execute(
                """
                INSERT INTO policy_reauthorizations (
                    id, original_decision_id, reauthorized_decision_id, scope_id
                ) VALUES (?, ?, ?, ?)
                """,
                (uuid4().hex, policy_decision_id, reauthorized_decision_id, request.scopeId),
            )
        return PolicyDecisionResponse(
            id=reauthorized_decision_id,
            scopeId=request.scopeId,
            target=original_decision["target"],
            action=original_decision["action"],
            status=outcome.status,
            reason=outcome.reason,
        )

    @app.post(
        "/api/policy-decisions/{policy_decision_id}/approvals",
        response_model=ApprovalResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def approve_required_action(policy_decision_id: str) -> ApprovalResponse:
        approval_id = uuid4().hex
        with _connect(resolved_database_path) as connection:
            decision = connection.execute(
                "SELECT decision_status FROM policy_decisions WHERE id = ?", (policy_decision_id,)
            ).fetchone()
            if decision is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy Decision not found")
            if decision["decision_status"] != "approval-required":
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Policy Decision does not require Approval")
            existing_approval = connection.execute(
                "SELECT id, approval_status FROM approvals WHERE policy_decision_id = ?", (policy_decision_id,)
            ).fetchone()
            if existing_approval is not None:
                return ApprovalResponse(
                    id=existing_approval["id"],
                    policyDecisionId=policy_decision_id,
                    status=existing_approval["approval_status"],
                )
            connection.execute(
                "INSERT INTO approvals (id, policy_decision_id, approval_status) VALUES (?, ?, ?)",
                (approval_id, policy_decision_id, "approved"),
            )
        return ApprovalResponse(id=approval_id, policyDecisionId=policy_decision_id, status="approved")

    @app.post("/api/policy-decisions/{policy_decision_id}/resume", response_model=ActionResumeResponse)
    def resume_approved_action(policy_decision_id: str) -> ActionResumeResponse:
        with _connect(resolved_database_path) as connection:
            decision = connection.execute(
                "SELECT * FROM policy_decisions WHERE id = ?", (policy_decision_id,)
            ).fetchone()
            if decision is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy Decision not found")
            if decision["decision_status"] != "approval-required":
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Policy Decision does not require Approval")
            approval = connection.execute(
                "SELECT id FROM approvals WHERE policy_decision_id = ? AND approval_status = ?",
                (policy_decision_id, "approved"),
            ).fetchone()
            if approval is None:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Owner Approval is required before resuming")
            scope = connection.execute("SELECT * FROM scopes WHERE id = ?", (decision["scope_id"],)).fetchone()
            assert scope is not None
            outcome = policy_engine.evaluate(
                scope_policy_input(scope), target=decision["target"], action=decision["action"]
            )
            if outcome.status == "approval-required":
                outcome = PolicyOutcome("allow", "Owner Approval permits the action")
            connection.execute(
                "INSERT INTO action_resumptions (id, policy_decision_id, approval_id, resume_status, reason) VALUES (?, ?, ?, ?, ?)",
                (uuid4().hex, policy_decision_id, approval["id"], outcome.status, outcome.reason),
            )
        return ActionResumeResponse(status=outcome.status, reason=outcome.reason)

    @app.post("/api/evidence-records", response_model=EvidenceRecordResponse, status_code=status.HTTP_201_CREATED)
    def create_evidence_record(request: CreateEvidenceRecordRequest) -> EvidenceRecordResponse:
        evidence_record_id = uuid4().hex
        with _connect(resolved_database_path) as connection:
            run = connection.execute("SELECT 1 FROM workflow_runs WHERE id = ?", (request.runId,)).fetchone()
            if run is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workflow run not found")
            connection.execute(
                """
                INSERT INTO evidence_records (
                    id, run_id, target, encrypted_summary, sha256, storage, vm_resident_path, availability, sensitive
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_record_id,
                    request.runId,
                    request.target,
                    evidence_cipher.encrypt(request.summary.encode()).decode(),
                    request.sha256,
                    request.storage,
                    request.vmResidentPath,
                    request.availability,
                    request.sensitive,
                ),
            )
            evidence_record = connection.execute(
                "SELECT * FROM evidence_records WHERE id = ?", (evidence_record_id,)
            ).fetchone()
        assert evidence_record is not None
        return evidence_record_response(evidence_record)

    @app.get("/api/evidence-records/{evidence_record_id}", response_model=EvidenceRecordResponse)
    def get_evidence_record(evidence_record_id: str) -> EvidenceRecordResponse:
        with _connect(resolved_database_path) as connection:
            evidence_record = connection.execute(
                "SELECT * FROM evidence_records WHERE id = ?", (evidence_record_id,)
            ).fetchone()
        if evidence_record is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence Record not found")
        return evidence_record_response(evidence_record)

    @app.post("/api/evidence-records/{evidence_record_id}/reveal", response_model=EvidenceRecordResponse)
    def reveal_sensitive_evidence(evidence_record_id: str) -> EvidenceRecordResponse:
        with _connect(resolved_database_path) as connection:
            evidence_record = connection.execute(
                "SELECT * FROM evidence_records WHERE id = ?", (evidence_record_id,)
            ).fetchone()
            if evidence_record is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence Record not found")
            if evidence_record["sensitive"]:
                connection.execute(
                    "INSERT INTO evidence_access_events (id, evidence_record_id, event_type) VALUES (?, ?, ?)",
                    (uuid4().hex, evidence_record_id, "evidence.revealed"),
                )
        return evidence_record_response(evidence_record, reveal_sensitive_summary=True)

    @app.get(
        "/api/evidence-records/{evidence_record_id}/access-events",
        response_model=list[EvidenceAccessEventResponse],
    )
    def list_evidence_access_events(evidence_record_id: str) -> list[EvidenceAccessEventResponse]:
        with _connect(resolved_database_path) as connection:
            events = connection.execute(
                "SELECT event_type FROM evidence_access_events WHERE evidence_record_id = ? ORDER BY rowid",
                (evidence_record_id,),
            ).fetchall()
        return [EvidenceAccessEventResponse(eventType=event["event_type"]) for event in events]

    @app.post("/api/findings", response_model=FindingResponse, status_code=status.HTTP_201_CREATED)
    def create_finding(request: CreateFindingRequest) -> FindingResponse:
        finding_id = uuid4().hex
        with _connect(resolved_database_path) as connection:
            run = connection.execute("SELECT 1 FROM workflow_runs WHERE id = ?", (request.runId,)).fetchone()
            if run is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workflow run not found")
            evidence_records = connection.execute(
                "SELECT id FROM evidence_records WHERE run_id = ? AND id IN ({})".format(
                    ", ".join("?" for _ in request.evidenceRecordIds)
                ),
                (request.runId, *request.evidenceRecordIds),
            ).fetchall()
            if {record["id"] for record in evidence_records} != set(request.evidenceRecordIds):
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Finding Evidence Records must belong to the Workflow Run")
            if request.runLogBundleIds:
                run_log_bundles = connection.execute(
                    "SELECT id FROM run_log_bundles WHERE id IN ({})".format(
                        ", ".join("?" for _ in request.runLogBundleIds)
                    ),
                    request.runLogBundleIds,
                ).fetchall()
                if {bundle["id"] for bundle in run_log_bundles} != set(request.runLogBundleIds):
                    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Finding Tool Calls must exist")
            if request.policyDecisionIds:
                policy_decisions = connection.execute(
                    "SELECT id FROM policy_decisions WHERE id IN ({})".format(
                        ", ".join("?" for _ in request.policyDecisionIds)
                    ),
                    request.policyDecisionIds,
                ).fetchall()
                if {decision["id"] for decision in policy_decisions} != set(request.policyDecisionIds):
                    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Finding Policy Decisions must exist")
            connection.execute(
                "INSERT INTO findings (id, title, target, run_id) VALUES (?, ?, ?, ?)",
                (finding_id, request.title, request.target, request.runId),
            )
            connection.executemany(
                "INSERT INTO finding_evidence_records (finding_id, evidence_record_id) VALUES (?, ?)",
                [(finding_id, evidence_record_id) for evidence_record_id in request.evidenceRecordIds],
            )
            connection.executemany(
                "INSERT INTO finding_run_log_bundles (finding_id, run_log_bundle_id) VALUES (?, ?)",
                [(finding_id, run_log_bundle_id) for run_log_bundle_id in request.runLogBundleIds],
            )
            connection.executemany(
                "INSERT INTO finding_policy_decisions (finding_id, policy_decision_id) VALUES (?, ?)",
                [(finding_id, policy_decision_id) for policy_decision_id in request.policyDecisionIds],
            )
            finding = connection.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
            assert finding is not None
            return finding_response(connection, finding)

    @app.get("/api/findings/{finding_id}", response_model=FindingResponse)
    def get_finding(finding_id: str) -> FindingResponse:
        with _connect(resolved_database_path) as connection:
            finding = connection.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
            if finding is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
            return finding_response(connection, finding)

    @app.get("/api/runs/{run_id}/findings", response_model=list[FindingResponse])
    def list_run_findings(run_id: str) -> list[FindingResponse]:
        with _connect(resolved_database_path) as connection:
            findings = connection.execute(
                "SELECT * FROM findings WHERE run_id = ? ORDER BY rowid", (run_id,)
            ).fetchall()
            return [finding_response(connection, finding) for finding in findings]

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
                "model": request.model,
                "reasoningEffort": request.reasoningEffort,
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
                    id, run_id, node_id, invocation_status, output_json, model,
                    reasoning_effort, timeout_seconds, resource_units
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    invocation_id,
                    run_id,
                    request.nodeId,
                    invocation_status,
                    json.dumps(output),
                    request.model,
                    request.reasoningEffort,
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
            model=request.model,
            reasoningEffort=request.reasoningEffort,
            timeoutSeconds=request.timeoutSeconds,
            resourceUnits=resource_units,
        )

    @app.get("/api/runs/{run_id}/ai-node-invocations", response_model=list[AiNodeInvocationResponse])
    def list_ai_node_invocations(run_id: str) -> list[AiNodeInvocationResponse]:
        with _connect(resolved_database_path) as connection:
            invocations = connection.execute(
                """
                SELECT id, run_id, node_id, invocation_status, output_json, model,
                       reasoning_effort, timeout_seconds, resource_units
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
                model=invocation["model"],
                reasoningEffort=invocation["reasoning_effort"],
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

    @app.get("/api/runs/{run_id}/agent-messages", response_model=list[AgentMessageResponse])
    def list_agent_messages(run_id: str) -> list[AgentMessageResponse]:
        with _connect(resolved_database_path) as connection:
            messages = connection.execute(
                """
                SELECT source_node_id, target_node_id, trigger, message_json
                FROM agent_messages
                WHERE run_id = ?
                ORDER BY rowid
                """,
                (run_id,),
            ).fetchall()
        return [
            AgentMessageResponse(
                sourceNodeId=message["source_node_id"],
                targetNodeId=message["target_node_id"],
                trigger=message["trigger"],
                message=json.loads(message["message_json"]),
            )
            for message in messages
        ]

    @app.post(
        "/api/crystal-flows/{crystal_flow_id}/runs",
        response_model=RunResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_run(crystal_flow_id: str, background_tasks: BackgroundTasks) -> RunResponse:
        run_id = uuid4().hex
        with _connect(resolved_database_path) as connection:
            flow_exists = connection.execute(
                "SELECT 1 FROM crystal_flows WHERE id = ?", (crystal_flow_id,)
            ).fetchone()
            if flow_exists is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Crystal Flow not found")
            connection.execute(
                "INSERT INTO workflow_runs (id, crystal_flow_id, status, stop_requested) VALUES (?, ?, ?, ?)",
                (run_id, crystal_flow_id, "created", 0),
            )
            connection.execute(
                """
                INSERT INTO execution_trail_events (event_type, run_id, crystal_flow_id)
                VALUES (?, ?, ?)
                """,
                ("run.created", run_id, crystal_flow_id),
            )
        background_tasks.add_task(orchestrate_run, run_id)
        return RunResponse(id=run_id, crystalFlowId=crystal_flow_id, status="created")

    @app.post("/api/runs/{run_id}/stop", response_model=RunResponse)
    def stop_run(run_id: str) -> RunResponse:
        with _connect(resolved_database_path) as connection:
            run = connection.execute(
                "SELECT id, crystal_flow_id, status FROM workflow_runs WHERE id = ?", (run_id,)
            ).fetchone()
            if run is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
            terminal_statuses = {"completed", "failed", "blocked", "stopped", "waiting-for-approval", "timeout", "resource-exceeded"}
            if run["status"] in terminal_statuses:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Run is already {run['status']}")
            connection.execute(
                "UPDATE workflow_runs SET status = ?, stop_requested = 1 WHERE id = ?",
                ("stopped", run_id),
            )
            connection.execute(
                "INSERT INTO execution_trail_events (event_type, run_id, crystal_flow_id) VALUES (?, ?, ?)",
                ("run.stop-requested", run_id, run["crystal_flow_id"]),
            )
            connection.execute(
                "INSERT INTO execution_trail_events (event_type, run_id, crystal_flow_id) VALUES (?, ?, ?)",
                ("run.stopped", run_id, run["crystal_flow_id"]),
            )
        return RunResponse(id=run_id, crystalFlowId=run["crystal_flow_id"], status="stopped")

    @app.get("/api/runs/{run_id}", response_model=RunResponse)
    def get_run(run_id: str) -> RunResponse:
        with _connect(resolved_database_path) as connection:
            run = connection.execute(
                "SELECT id, crystal_flow_id, status FROM workflow_runs WHERE id = ?", (run_id,)
            ).fetchone()
        if run is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
        return RunResponse(id=run["id"], crystalFlowId=run["crystal_flow_id"], status=run["status"])

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
