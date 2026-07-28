# Adaptive Security Orchestration

The domain for coordinating authorized cybersecurity assessment work while preserving enforceable scope, human oversight, and auditability.

## Language

**Assessment Workflow**:
A user-defined graph of authorized security-assessment tasks and their dependencies.
_Avoid_: Attack plan, scan sequence

**Crystal Flow**:
The versioned workflow definition and governance layer that specifies an Assessment Workflow's graph, permitted nodes, approved agents and tools, valid branches, runtime-adjustable parameters, performance profiles, budgets, policy bindings, and Approval gates.
_Avoid_: Workflow template, configuration file

**Authorization Boundary**:
The complete set of actions, Scope, permissions, tools, targets, and workflow structure explicitly permitted by the active Crystal Flow.
_Avoid_: Implied permission, default access

**Workflow Node**:
A visible unit of an Assessment Workflow representing an agent, tool task, verification step, or Approval gate.
_Avoid_: Step, box

**Agent Message**:
A structured, auditable handoff of task context, evidence, and result data from one Workflow Node to another.
_Avoid_: Prompt, chat message

**Verification Step**:
A Workflow Node that evaluates a preceding result before it may be used by a later task or action.
_Avoid_: Validation, review

**Bounded Loop**:
An explicitly configured repeat path on a Workflow Node with a finite attempt limit, timeout, budget, retry condition, and exit path.
_Avoid_: Retry forever, agent loop

**Node Timeout**:
The maximum time a Workflow Node may wait for an agent, tool, or downstream response before it is considered stalled.
_Avoid_: Scope Window, runtime limit

**Timeout Report**:
The diagnostic record explaining why a Workflow Node timed out, returned to the Owner when the run pauses for review.
_Avoid_: Error message, failure log

**Run Version**:
The immutable configuration snapshot used to execute a specific workflow run.
_Avoid_: Live configuration, current workflow

**Planner**:
The initiating planning process that proposes approved Specialist Agents, valid branches, and permitted runtime choices from the active Crystal Flow.
_Avoid_: Orchestrator, autonomous controller

**Plugin**:
A versioned extension that supplies an agent or tool capability to the platform and declares its capabilities, permissions, schemas, and resource requirements in a manifest.
_Avoid_: Script, integration

**Plugin Manifest**:
The machine-readable declaration of a Plugin's capabilities, requested permissions, input and output schemas, risk category, and resource limits.
_Avoid_: Metadata, plugin configuration

**Approved Plugin**:
A Plugin permitted for use after the required trust checks and administrator authorization; it must also be enabled in the active Crystal Flow.
_Avoid_: Installed plugin, available plugin

**Owner**:
The single MVP user with full authority to manage Crystal Flows, Plugins, policies, execution, Approvals, Findings, and Execution Trails.
_Avoid_: Administrator, operator, approver

**Specialist Agent**:
A bounded AI worker selected by the Owner through a Crystal Flow to perform a specific assessment capability within an Assessment Workflow.
_Avoid_: Bot, autonomous hacker

**Agent Catalog**:
The set of Approved Plugins that provide built-in or Owner-created Specialist Agents available for an Owner to enable and compose in a Crystal Flow.
_Avoid_: Fixed pipeline, agent list

**Custom Agent**:
An Owner-defined, governed configuration of approved agents, Plugins, and tools for a particular assessment need; it declares its objective, instructions, inputs, available capabilities, permissions, and execution limits.
_Avoid_: Ad hoc bot, ungoverned agent

**Adaptive Planning**:
The Planner's ability to select approved tools and Specialist Agents and adjust strategies, retries, branches, and resource profiles within the active Crystal Flow and Scope.
_Avoid_: Self-modification, unrestricted autonomy

**Adaptation Trigger**:
A new evidence result, verification failure, node timeout, permitted branch condition, or approaching resource limit that may cause Adaptive Planning to select a permitted alternative in the active Crystal Flow.
_Avoid_: Autonomous exception, dynamic rule

**Capability Proposal**:
A versioned request for the Owner to approve new capabilities when the active Crystal Flow cannot satisfy a task; it does not change the system autonomously.
_Avoid_: Dynamic installation, self-upgrade

**Scope**:
The explicit authorization for an assessment, including its permitted targets, workspace, tools, filesystem and network access, credentials, resource limits, active time window, and Unattended Execution setting.
_Avoid_: Permission, engagement

**Scope Window**:
The configured start and expiry time during which a Scope is valid; it is required by default.
_Avoid_: Schedule, runtime

**Permitted Target**:
A file, directory, repository, forensic image, VM, container, URL, domain, IP address, or lab instance explicitly included in Scope.
_Avoid_: Asset, victim, host

**Permitted Workspace**:
The Owner-selected execution environment in which agents may access files, tools, and other authorized resources.
_Avoid_: Working directory, sandbox

**Run Workspace**:
An isolated workspace for one workflow run containing only its permitted inputs and outputs.
_Avoid_: Shared directory, host workspace

**Execution Environment**:
The isolated VM or other runtime in which an agent tool executes under Scope-derived filesystem, credential, resource, and network permissions.
_Avoid_: Host machine, unrestricted shell

**Resource Limits**:
The maximum permitted execution rate, concurrency, runtime, tool calls, retries, and other computational consumption for a workflow run.
_Avoid_: Quota, throttle

**Policy Engine**:
The OPA-backed authority that evaluates a proposed action against Scope and organizational safety rules.
_Avoid_: Guardrail, permissions check

**Policy Decision**:
The allow, deny, or Approval-required result returned by the Policy Engine for a proposed action.
_Avoid_: Permission, rule result

**Policy Denial**:
A Policy Decision that blocks an action and identifies the Policy Set rule and reason; it remains in the Execution Trail even if the Owner later changes authorization.
_Avoid_: Failed approval, override

**Policy Set**:
A versioned collection of OPA rules and safe Owner-configurable controls governing Scope, resource limits, Approval Policy, and Plugin allow-lists.
_Avoid_: Ad hoc rules, runtime override

**Approval**:
A human authorization required before a proposed high-risk action may proceed.
_Avoid_: Confirmation, sign-off

**Approval Policy**:
The per-action-category rule that determines whether an action requires Approval; it cannot override Scope or other mandatory safety checks.
_Avoid_: Autonomy toggle, bypass switch

**Unattended Execution**:
Execution without pausing for human confirmation, permitted only for actions inside the active Crystal Flow's Authorization Boundary.
_Avoid_: Unrestricted automation, autonomous mode

**Exploitation Attempt**:
An action intended to validate whether a discovered weakness can be used to achieve unauthorized capability on a target.
_Avoid_: Exploit, attack

**Authorized Lab Environment**:
An isolated environment explicitly designated in Scope for automated Exploitation Attempts.
_Avoid_: Sandbox, CTF

**Finding**:
A security-relevant result supported by Evidence Provenance and linked to its Execution Trail.
_Avoid_: Alert, vulnerability report

**Evidence Provenance**:
The traceable explanation of how a Finding was produced, linking its claim to the relevant Workflow Nodes, Agent Messages, tool calls, captured artifacts, timestamps, target, versions, and policy decisions.
_Avoid_: Explanation, AI reasoning

**Evidence Artifact**:
A captured raw tool output or other source material that supports a Finding and is stored with an integrity hash.
_Avoid_: Attachment, proof

**Evidence Record**:
The host-stored Finding evidence summary, provenance, integrity hash, and metadata used by the UI and SQLite database.
_Avoid_: Raw artifact, log entry

**VM-Resident Artifact**:
A large or raw Evidence Artifact, such as a memory image, retained in its Execution Environment's Run Workspace and referenced by an Evidence Record on the Owner host; if unavailable after cleanup, its host-side record remains with that status and last-known location.
_Avoid_: Database blob, host attachment

**Sensitive Evidence**:
Evidence Artifact containing secrets or other sensitive material; it is retained encrypted, shown masked by default, and may be revealed, exported, or accessed in decrypted form only through explicitly authorized, auditable actions.
_Avoid_: Secret log, private artifact

**Model Data Access**:
The permission for the configured AI runtime to receive target data or Sensitive Evidence during workflow execution.
_Avoid_: Implicit prompt sharing, private inference

**Model Call Record**:
An Execution Trail record of the AI runtime, requesting node, and data-access decision for an AI invocation.
_Avoid_: Prompt log, AI history

**Sequential AI Execution**:
The MVP runtime model in which one currently running Codex CLI session processes AI-powered Workflow Nodes one at a time.
_Avoid_: Parallel agents, per-node process

**Session Adapter**:
The local bridge that serializes AI-powered node requests from the orchestration service to the running Codex CLI session and returns structured results.
_Avoid_: Manual copy-paste, model provider

**Evidence Access Event**:
An Execution Trail record of a Sensitive Evidence reveal or export.
_Avoid_: View log, download history

**Execution Trail**:
The centralized, immutable, auditable record on the Owner host of workflow decisions, agent actions, policy evaluations, approvals, and resulting evidence.
_Avoid_: Logs, history

**Run Log Bundle**:
The structured node, tool, SSH-command, status, and diagnostic records returned from an Execution Environment to the Owner host for storage in the Execution Trail.
_Avoid_: VM-local logs, console output

**Node Status**:
The real-time lifecycle state of a Workflow Node during a workflow run.
_Avoid_: Progress, job status

**Evaluation Benchmark**:
An isolated challenge environment used to measure the platform; CTFs are Evaluation Benchmarks rather than the product's primary use case.
_Avoid_: Main target, production environment
