## Problem Statement

Authorized security assessment work is difficult to coordinate safely when discovery, analysis, verification, approval, tools, evidence, and reporting are spread across disconnected manual processes. Owners need a self-hosted platform that makes these workflows visible and adaptive while enforcing authorization boundaries and preserving defensible evidence.

## Solution

Build the Adaptive Security Orchestration Platform MVP: a self-hosted, single-Owner platform for authorized lab and explicitly scoped red-team or penetration-testing workflows. The Owner uses a React Flow Workflow Canvas to compose versioned Crystal Flows from approved agents, tools, verification steps, and Approval gates. LangGraph executes the flow sequentially through one currently running Codex CLI session, while OPA evaluates every proposed action against Scope, Policy Set, budgets, and Approval Policy.

Security and forensic tools execute over SSH in isolated Kali or Debian VMs. The Owner host is the system of record for Findings, Evidence Records, policy decisions, and the Execution Trail; large raw artifacts remain in VM Run Workspaces and are linked by hash and metadata. CTFs are Evaluation Benchmarks, not the primary product purpose.

## User Stories

1. As an Owner, I want to create a Crystal Flow visually, so that I can express an authorized assessment without manually coordinating each task.
2. As an Owner, I want to drag built-in Specialist Agents onto the Workflow Canvas, so that I can compose a workflow from supported capabilities.
3. As an Owner, I want to create a Custom Agent from approved capabilities, instructions, permissions, and limits, so that I can tailor a flow without adding executable code.
4. As an Owner, I want to connect nodes with valid branches and structured Agent Messages, so that evidence and results move predictably between tasks.
5. As an Owner, I want to configure Bounded Loops on nodes, so that verification or recovery can repeat safely.
6. As an Owner, I want every loop to have attempt, timeout, budget, condition, exit-path, and Approval settings, so that it cannot become open-ended.
7. As an Owner, I want to define Scope before launching a run, so that permitted targets, workspace, tools, filesystem/network access, credentials, limits, and time window are explicit.
8. As an Owner, I want to select at least one Permitted Target, including files, repositories, forensic images, VMs, containers, URLs, domains, IP addresses, or lab instances, so that work is always tied to authorization.
9. As an Owner, I want to choose a Permitted Workspace, so that agents only access approved inputs and outputs.
10. As an Owner, I want to configure Resource Limits for rate, concurrency, runtime, tool calls, and retries, so that a run cannot overload a target or platform.
11. As an Owner, I want a Scope Window by default, so that a run cannot start or continue outside its authorization period.
12. As an Owner, I want to enable Unattended Execution only within a Crystal Flow Authorization Boundary, so that human pauses may be removed without removing safety controls.
13. As an Owner, I want each action evaluated by the Policy Engine, so that Scope, policies, limits, and permissions are enforced consistently.
14. As an Owner, I want a Policy Denial to name the blocked action, rule, and reason, so that I can understand why a graph paused or stopped.
15. As an Owner, I want to reauthorize only by creating a new version of Scope, Crystal Flow, or Policy Set, so that denials cannot be silently overridden.
16. As an Owner, I want high-risk actions to pause at Approval gates when required, so that I retain control over impactful work.
17. As an Owner, I want plugins to be approved and enabled in the active Crystal Flow, so that untrusted or irrelevant capabilities cannot execute.
18. As an Owner, I want external plugins integrity-checked with manifests, so that their capabilities and requested permissions are reviewable.
19. As an Owner, I want the Planner to adapt to new evidence, verification failures, timeouts, permitted branches, and approaching limits, so that a run can recover within its declared authority.
20. As an Owner, I want the Planner to propose missing capabilities instead of modifying the system, so that adaptation never becomes self-modification.
21. As an Owner, I want live node status and data-transfer visibility, so that I can understand what the current run is doing.
22. As an Owner, I want to inspect a node or edge for messages, tool calls, logs, policy decisions, and execution history, so that I can audit the run.
23. As an Owner, I want a timeout to return a Timeout Report and pause for review, so that failures are explainable rather than silent.
24. As an Owner, I want each tool task to run in a scoped isolated VM workspace, so that it cannot access the host, another run, or undeclared targets by default.
25. As an Owner, I want tool execution to use Kali for security/forensic tools and Debian for browser automation, so that capabilities run in appropriate isolated environments.
26. As an Owner, I want structured Run Log Bundles sent to the host, so that the UI and SQLite database are the authoritative audit source.
27. As an Owner, I want each Finding to include Evidence Provenance, so that I can see exactly how it was found.
28. As an Owner, I want raw and sensitive evidence retained where relevant, so that findings remain defensible.
29. As an Owner, I want Sensitive Evidence encrypted and masked by default, so that it is retained without being casually exposed.
30. As an Owner, I want approved nodes to access decrypted Sensitive Evidence only when explicitly granted, so that raw data use is limited and auditable.
31. As an Owner, I want the host to retain Findings, Evidence Records, hashes, and metadata while large raw artifacts remain on the VM, so that the platform remains responsive without losing provenance.
32. As an Owner, I want unavailable VM artifacts to remain visible as unavailable with their last-known location, so that cleanup cannot silently erase evidence history.
33. As an Owner, I want the five reference agents—Recon, Repository/Code Review, Web/API Review, Verification, and Reporting—available to compose, so that I can demonstrate useful workflows immediately.
34. As an Owner, I want all AI nodes to use one serialized live Codex CLI session via a Session Adapter, so that the MVP is controlled and auditable.
35. As an Owner, I want benchmark workflows to demonstrate safe adaptation, policy blocking, approvals, evidence reconstruction, and timeout recovery, so that the MVP can be evaluated credibly.

## Implementation Decisions

- The MVP is a single-Owner, self-hosted system. Multi-user roles and RBAC are deferred.
- React and TypeScript provide the Workflow Canvas and execution/audit views; React Flow renders and edits Crystal Flows.
- A Python service uses LangGraph for orchestration, Pydantic for structured contracts, and OPA as the Policy Engine.
- Crystal Flow is a versioned governance layer that declares graph structure, nodes, approved agents/tools, valid branches, policies, budgets, performance profiles, runtime-adjustable parameters, and Approval gates.
- The Planner can select only approved agents, tools, branches, retries, and resource profiles permitted by the active Crystal Flow and Scope. It creates Capability Proposals rather than code or policy changes.
- AI-powered nodes execute serially through the currently running Codex CLI. A local Session Adapter accepts structured node requests and returns structured results, with per-node timeouts and resource limits.
- The Policy Engine returns allow, deny, or Approval-required. A denial is an immutable trail event; reauthorization always produces and evaluates a new version.
- Plugins require manifests. Built-ins are trusted; external MVP plugins need administrator/Owner approval and checksum verification. Signed immutable registry artifacts are future work.
- Tool execution is remote over SSH: Kali supports security and forensic tasks; Debian supports browser automation. Each run receives a Run Workspace and Scope-derived filesystem, credential, resource, and network permissions.
- The host stores workflow definitions, versions, runs, Findings, Evidence Records, hashes, and the Execution Trail in SQLite/host storage. The VMs return structured Run Log Bundles.
- Large or raw artifacts remain VM-Resident Artifacts. Their Evidence Record on the host stores provenance, hash, status, and last-known location; explicit archiving is available before VM cleanup.
- Sensitive Evidence is encrypted, masked by default, and auditable on reveal/export/decrypted agent access. The MVP permits the configured Codex runtime to receive raw data and records every Model Call Record.

## Testing Decisions

- Test externally observable behavior, policy outcomes, persisted trail/evidence state, and UI interactions—not internal call order or framework implementation.
- Test the Workflow Run service with complete flows that produce node statuses, structured messages, Findings, and Execution Trail records.
- Test the Policy Engine boundary for allow, deny, Approval-required, expired Scope, resource limits, and attempts outside the Authorization Boundary.
- Test the VM Runner boundary with a controlled SSH fixture to verify Run Workspace isolation, allowed-target enforcement, Run Log Bundle collection, and artifact references.
- Test the Evidence service for provenance reconstruction, hashing, sensitive-data masking/access auditing, hybrid artifact availability, and cleanup behavior.
- Test the React Flow UI end-to-end for drag/drop node authoring, connections, configuration validation, live status, node/edge inspection, Approval, Policy Denial display, and Finding provenance views.
- Use isolated lab environments and CTF Evaluation Benchmarks for acceptance tests; never target undeclared systems.

## Out of Scope

- Multi-user collaboration, RBAC, teams, and delegated roles.
- Parallel agents, per-node Codex subprocesses, or multiple model providers.
- Automatic plugin code creation or autonomous plugin installation.
- Signed third-party registries, cloud deployment, Postgres/object storage migrations, and automatic archival storage.
- Open-ended loops, dynamic scope expansion, policy bypasses, or automatic recovery from Policy Denials.
- Production-target assessment without explicit authorized Scope.

## Further Notes

- The default approval requirement for Exploitation Attempts remains enabled. Unattended Execution may allow defined actions only within the active Authorization Boundary and never bypasses isolation, Scope, policy, limits, or audit recording.
- The system’s primary purpose is authorized security orchestration. CTFs are used to measure success, not as the central product domain.
- Detailed vocabulary and durable design decisions live in the root glossary and ADRs.
