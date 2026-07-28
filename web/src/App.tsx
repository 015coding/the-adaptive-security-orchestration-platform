import { DragEvent, FormEvent, useEffect, useState } from "react";
import {
  addEdge,
  applyEdgeChanges,
  applyNodeChanges,
  Background,
  Connection,
  Controls,
  Edge,
  Handle,
  MiniMap,
  Node,
  NodeProps,
  OnConnect,
  Position,
  ReactFlow,
  ReactFlowInstance,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

type NodeKind = "recon-agent" | "verification-step" | "approval-gate" | "custom-agent";

type WorkflowNodeData = {
  kind: NodeKind;
  label: string;
  config: Record<string, unknown>;
  status?: string;
};

type WorkflowNode = Node<WorkflowNodeData>;

type CrystalFlow = {
  id: string;
  name: string;
  version: number;
  nodes: Array<{
    id: string;
    type: NodeKind;
    label: string;
    position: { x: number; y: number };
    config: Record<string, unknown>;
  }>;
  edges: Array<{ id: string; source: string; target: string }>;
};

type WorkflowRun = {
  id: string;
  crystalFlowId: string;
  status: string;
};

type AuditEvent = {
  eventType: string;
  runId: string;
  crystalFlowId: string;
};

type NodeStatus = { nodeId: string; status: string };

type AgentMessage = {
  sourceNodeId: string;
  targetNodeId: string | null;
  trigger: string;
  message: Record<string, unknown>;
};

type AiNodeInvocation = {
  id: string;
  nodeId: string;
  status: string;
  output: Record<string, unknown>;
  model: string | null;
  reasoningEffort: string;
  timeoutSeconds: number;
  resourceUnits: number;
};

type Finding = {
  id: string;
  title: string;
  target: string;
  provenance: {
    nodeIds: string[];
    agentMessages: AgentMessage[];
    toolCalls: Array<{ id: string; status: string; stdout: string; stderr: string }>;
    policyDecisions: Array<{ id: string; status: string; reason: string }>;
    evidenceArtifacts: Array<{
      id: string;
      summary: string;
      sha256: string;
      storage: string;
      vmResidentPath: string | null;
      availability: string;
      sensitive: boolean;
    }>;
  };
};

type ReferenceCatalog = {
  benchmarkFlowId: string;
};

type ScopeResponse = {
  id: string;
  version: number;
};

type ExecutionEnvironment = {
  environment: "kali" | "debian";
  sshTarget: string;
};

const palette: Array<{ kind: NodeKind; label: string }> = [
  { kind: "recon-agent", label: "Recon Agent" },
  { kind: "verification-step", label: "Verification Step" },
  { kind: "approval-gate", label: "Approval Gate" },
  { kind: "custom-agent", label: "Custom Agent" },
];

const nodeKindLabels: Record<NodeKind, string> = {
  "recon-agent": "RECON",
  "verification-step": "VERIFY",
  "approval-gate": "APPROVAL",
  "custom-agent": "AGENT",
};

function SecurityNode({ data, selected }: NodeProps<WorkflowNode>) {
  return (
    <div className={`security-node ${selected ? "is-selected" : ""} status-${data.status ?? "idle"}`}>
      <Handle type="target" position={Position.Left} />
      <div className="security-node__header">
        <span className={`node-glyph node-glyph--${data.kind}`}>{nodeKindLabels[data.kind].slice(0, 1)}</span>
        <span>{nodeKindLabels[data.kind]}</span>
        <span className="node-live-dot" aria-label={data.status ?? "idle"} />
      </div>
      <strong>{data.label}</strong>
      <small>{data.status ?? (typeof data.config.model === "string" ? data.config.model : "Session default")}</small>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

const nodeTypes = { security: SecurityNode };

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  if (!response.ok) {
    throw new Error(`Request failed with ${response.status}`);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json() as Promise<T>;
}

function toCanvasNode(node: CrystalFlow["nodes"][number]): WorkflowNode {
  return {
    id: node.id,
    type: "security",
    position: node.position,
    data: { kind: node.type, label: node.label, config: node.config },
  };
}

function toCanvasEdge(edge: CrystalFlow["edges"][number]): Edge {
  return { id: edge.id, source: edge.source, target: edge.target };
}

function InspectionList({ label, values }: { label: string; values: string[] }) {
  return (
    <section className="inspection-list" aria-label={label}>
      <h4>{label}</h4>
      {values.length === 0 ? <p className="muted">No records yet.</p> : (
        <ul>{values.map((value, index) => <li key={`${label}-${index}`}>{value}</li>)}</ul>
      )}
    </section>
  );
}

function localDateTimeValue(date: Date): string {
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

function CtfSetupPage({ onCreated }: { onCreated: (flow: CrystalFlow) => void }) {
  const [challengeName, setChallengeName] = useState("CTF assessment");
  const [target, setTarget] = useState("");
  const [workspace, setWorkspace] = useState("/srv/crystal-flow/ctf-01");
  const [environment, setEnvironment] = useState<"kali" | "debian">("kali");
  const [sshTarget, setSshTarget] = useState("codex-kali");
  const [startsAt, setStartsAt] = useState(localDateTimeValue(new Date()));
  const [expiresAt, setExpiresAt] = useState(localDateTimeValue(new Date(Date.now() + 4 * 60 * 60 * 1000)));
  const [maxRequestsPerSecond, setMaxRequestsPerSecond] = useState(5);
  const [maxConcurrentTasks, setMaxConcurrentTasks] = useState(1);
  const [maxRuntimeSeconds, setMaxRuntimeSeconds] = useState(600);
  const [authorizedLab, setAuthorizedLab] = useState(true);
  const [includeExploitation, setIncludeExploitation] = useState(false);
  const [unattendedExecution, setUnattendedExecution] = useState(false);
  const [model, setModel] = useState("gpt-5.6-terra");
  const [reasoningEffort, setReasoningEffort] = useState("medium");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [configuredEnvironments, setConfiguredEnvironments] = useState<ExecutionEnvironment[]>([]);

  useEffect(() => {
    request<ExecutionEnvironment[]>("/api/execution-environments")
      .then((environments) => {
        setConfiguredEnvironments(environments);
        const configured = environments.find((item) => item.environment === environment);
        if (configured) setSshTarget(configured.sshTarget);
      })
      .catch(() => undefined);
  }, []);

  function changeEnvironment(nextEnvironment: "kali" | "debian") {
    setEnvironment(nextEnvironment);
    setSshTarget(
      configuredEnvironments.find((item) => item.environment === nextEnvironment)?.sshTarget
      ?? (nextEnvironment === "kali" ? "codex-kali" : "codex-debian"),
    );
  }

  async function createCtfWorkspace(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);
    if (new Date(startsAt) >= new Date(expiresAt)) {
      setFormError("Expiry time must be later than the start time.");
      return;
    }
    if (includeExploitation && !authorizedLab) {
      setFormError("Exploitation can only be enabled for an authorized lab environment.");
      return;
    }

    setSubmitting(true);
    try {
      await request<ExecutionEnvironment>(`/api/execution-environments/${environment}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sshTarget }),
      });
      const allowedActions = ["reconnaissance", "verification"];
      if (includeExploitation) allowedActions.push("exploitation-attempt");
      const scope = await request<ScopeResponse>("/api/scopes", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          targets: [target],
          workspace,
          allowedActions,
          resourceLimits: { maxRequestsPerSecond, maxConcurrentTasks, maxRuntimeSeconds },
          startsAt: new Date(startsAt).toISOString(),
          expiresAt: new Date(expiresAt).toISOString(),
          unattendedExecution,
          authorizedLabEnvironment: authorizedLab,
        }),
      });
      const created = await request<CrystalFlow>("/api/crystal-flows", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: challengeName }),
      });
      const approvalRequired = includeExploitation && !unattendedExecution;
      const reconTarget = approvalRequired ? "ctf-approval" : "ctf-verification";
      const nodes: CrystalFlow["nodes"] = [
        {
          id: "ctf-recon",
          type: "recon-agent",
          label: "CTF Recon Agent",
          position: { x: 80, y: 120 },
          config: {
            scopeId: scope.id, target, workspace, environment, sshTarget, model, reasoningEffort,
            action: "reconnaissance", branches: { completed: reconTarget },
          },
        },
        {
          id: "ctf-verification",
          type: "verification-step",
          label: includeExploitation ? "Exploit & Verify" : "CTF Verification",
          position: { x: approvalRequired ? 600 : 360, y: 120 },
          config: {
            scopeId: scope.id, target, workspace, environment, sshTarget, model, reasoningEffort,
            action: includeExploitation ? "exploitation-attempt" : "verification",
          },
        },
      ];
      const edges: CrystalFlow["edges"] = [];
      if (approvalRequired) {
        nodes.splice(1, 0, {
          id: "ctf-approval",
          type: "approval-gate",
          label: "Owner Approval",
          position: { x: 340, y: 120 },
          config: { scopeId: scope.id, branches: { approved: "ctf-verification" } },
        });
        edges.push(
          { id: "ctf-recon-approval", source: "ctf-recon", target: "ctf-approval" },
          { id: "ctf-approval-verification", source: "ctf-approval", target: "ctf-verification" },
        );
      } else {
        edges.push({ id: "ctf-recon-verification", source: "ctf-recon", target: "ctf-verification" });
      }
      const saved = await request<CrystalFlow>(`/api/crystal-flows/${created.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nodes, edges }),
      });
      onCreated(saved);
    } catch (requestError) {
      setFormError(requestError instanceof Error ? requestError.message : "Unable to create CTF setup");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="section-page ctf-setup-page">
      <div className="page-intro">
        <span>AUTHORIZED LAB CONFIGURATION</span>
        <h2>CTF Challenge Setup</h2>
        <p>Configure the Instance, isolated VM, Scope, runtime limits, approvals, and AI profile. Challenge files remain outside this form and can be copied into the declared VM Workspace separately.</p>
      </div>
      <form className="ctf-form" onSubmit={createCtfWorkspace}>
        <section className="page-card">
          <div className="page-card-heading"><span>CHALLENGE</span><b>01</b></div>
          <div className="form-grid">
            <label><span>Challenge name</span><input required value={challengeName} onChange={(event) => setChallengeName(event.target.value)} /></label>
            <label><span>Instance target</span><input placeholder="http://10.10.10.50:8080" required value={target} onChange={(event) => setTarget(event.target.value)} /></label>
          </div>
        </section>
        <section className="page-card">
          <div className="page-card-heading"><span>ISOLATED EXECUTION</span><b>02</b></div>
          <div className="form-grid three">
            <label><span>Environment</span><select value={environment} onChange={(event) => changeEnvironment(event.target.value as "kali" | "debian")}><option value="kali">Kali VM</option><option value="debian">Debian VM</option></select></label>
            <label><span>SSH alias</span><input required value={sshTarget} onChange={(event) => setSshTarget(event.target.value)} /></label>
            <label className="wide"><span>VM Workspace</span><input required value={workspace} onChange={(event) => setWorkspace(event.target.value)} /></label>
          </div>
          <p className="form-note">The SSH alias is saved to the Backend and takes effect immediately. The Workspace must already exist inside the selected VM.</p>
        </section>
        <section className="page-card">
          <div className="page-card-heading"><span>SCOPE WINDOW &amp; LIMITS</span><b>03</b></div>
          <div className="form-grid three">
            <label><span>Starts at</span><input required type="datetime-local" value={startsAt} onChange={(event) => setStartsAt(event.target.value)} /></label>
            <label><span>Expires at</span><input required type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></label>
            <label><span>Requests / second</span><input min="1" required type="number" value={maxRequestsPerSecond} onChange={(event) => setMaxRequestsPerSecond(Number(event.target.value))} /></label>
            <label><span>Concurrent tasks</span><input min="1" required type="number" value={maxConcurrentTasks} onChange={(event) => setMaxConcurrentTasks(Number(event.target.value))} /></label>
            <label><span>Task timeout (seconds)</span><input min="1" required type="number" value={maxRuntimeSeconds} onChange={(event) => setMaxRuntimeSeconds(Number(event.target.value))} /></label>
          </div>
        </section>
        <section className="page-card">
          <div className="page-card-heading"><span>GOVERNANCE &amp; AI</span><b>04</b></div>
          <div className="form-grid">
            <label><span>Node model</span><select value={model} onChange={(event) => setModel(event.target.value)}><option value="gpt-5.6-sol">GPT-5.6 Sol</option><option value="gpt-5.6-terra">GPT-5.6 Terra</option><option value="gpt-5.6-luna">GPT-5.6 Luna</option></select></label>
            <label><span>Reasoning effort</span><select value={reasoningEffort} onChange={(event) => setReasoningEffort(event.target.value)}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="xhigh">Extra high</option></select></label>
          </div>
          <div className="toggle-grid">
            <label><input checked={authorizedLab} onChange={(event) => { setAuthorizedLab(event.target.checked); if (!event.target.checked) setUnattendedExecution(false); }} type="checkbox" /><span><strong>Authorized lab</strong><small>Confirm this Instance is an explicitly authorized CTF environment.</small></span></label>
            <label><input checked={includeExploitation} onChange={(event) => setIncludeExploitation(event.target.checked)} type="checkbox" /><span><strong>Allow exploitation attempts</strong><small>Add exploitation to Scope and generated Flow.</small></span></label>
            <label className={!authorizedLab ? "is-disabled" : ""}><input checked={unattendedExecution} disabled={!authorizedLab} onChange={(event) => setUnattendedExecution(event.target.checked)} type="checkbox" /><span><strong>Human Approval Bypass</strong><small>Allow unattended execution inside this exact authorized Scope.</small></span></label>
          </div>
        </section>
        {formError && <div className="form-error" role="alert">{formError}</div>}
        <div className="ctf-form-actions"><span>Files are not uploaded by this page.</span><button className="button primary" disabled={submitting} type="submit">{submitting ? "Creating…" : "Create Scope & Crystal Flow"}</button></div>
      </form>
    </main>
  );
}

function keepValidBranches(workflowNodes: WorkflowNode[], workflowEdges: Edge[]): WorkflowNode[] {
  const validRoutes = new Set(workflowEdges.map((edge) => `${edge.source}\0${edge.target}`));
  return workflowNodes.map((node) => {
    const configuredBranches = node.data.config.branches;
    if (
      !configuredBranches
      || typeof configuredBranches !== "object"
      || Array.isArray(configuredBranches)
    ) {
      return node;
    }

    const branches = Object.fromEntries(
      Object.entries(configuredBranches).filter(([, target]) => (
        typeof target === "string" && validRoutes.has(`${node.id}\0${target}`)
      )),
    );
    const boundedLoop = node.data.config.boundedLoop;
    const boundedLoopConfig = (
      boundedLoop
      && typeof boundedLoop === "object"
      && !Array.isArray(boundedLoop)
    ) ? boundedLoop as Record<string, unknown> : null;
    const boundedLoopTrigger = (
      boundedLoopConfig && typeof boundedLoopConfig.trigger === "string"
    ) ? boundedLoopConfig.trigger : null;
    const nextConfig: Record<string, unknown> = { ...node.data.config, branches };
    if (boundedLoopTrigger && !(boundedLoopTrigger in branches)) {
      delete nextConfig.boundedLoop;
    }
    return { ...node, data: { ...node.data, config: nextConfig } };
  });
}

export function App() {
  const [pathname, setPathname] = useState(window.location.pathname);
  const page = pathname.startsWith("/ctf-setup")
    ? "ctf"
    : pathname.startsWith("/runs")
    ? "runs"
    : pathname.startsWith("/findings")
      ? "findings"
      : pathname.startsWith("/policy")
        ? "policy"
        : "workflows";
  const routeFlowId = page === "workflows"
    ? pathname.match(/^\/workflows\/([^/]+)$/)?.[1] ?? null
    : null;
  const pageTitle = {
    workflows: "Workflow Studio",
    ctf: "CTF Challenge Setup",
    runs: "Run History",
    findings: "Findings",
    policy: "Policy & Scope",
  }[page];
  const [theme, setTheme] = useState<"dark" | "light">(() => (
    localStorage.getItem("crystal-flow-theme") === "light" ? "light" : "dark"
  ));
  const [flowName, setFlowName] = useState("");
  const [flow, setFlow] = useState<CrystalFlow | null>(null);
  const [savedFlows, setSavedFlows] = useState<CrystalFlow[]>([]);
  const [nodes, setNodes] = useState<WorkflowNode[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [reactFlow, setReactFlow] = useState<ReactFlowInstance<WorkflowNode, Edge> | null>(null);
  const [run, setRun] = useState<WorkflowRun | null>(null);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [nodeStatuses, setNodeStatuses] = useState<NodeStatus[]>([]);
  const [agentMessages, setAgentMessages] = useState<AgentMessage[]>([]);
  const [aiNodeInvocations, setAiNodeInvocations] = useState<AiNodeInvocation[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    request<CrystalFlow[]>("/api/crystal-flows")
      .then(setSavedFlows)
      .catch(() => setError("Unable to load saved Crystal Flows"));
  }, []);

  useEffect(() => {
    const onPopState = () => setPathname(window.location.pathname);
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  function navigate(path: string, options?: { replace?: boolean }) {
    if (options?.replace) {
      window.history.replaceState(null, "", path);
    } else {
      window.history.pushState(null, "", path);
    }
    setPathname(path);
  }

  useEffect(() => {
    if (!routeFlowId || flow?.id === routeFlowId) return;
    request<CrystalFlow>(`/api/crystal-flows/${routeFlowId}`)
      .then((selectedFlow) => openFlow(selectedFlow, false))
      .catch(() => {
        setError("Unable to open the requested Crystal Flow");
        navigate("/workflows", { replace: true });
      });
  }, [routeFlowId]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("crystal-flow-theme", theme);
  }, [theme]);

  const selectedNode = nodes.find((node) => node.id === selectedNodeId) ?? null;
  const selectedEdge = edges.find((edge) => edge.id === selectedEdgeId) ?? null;
  const selectedFinding = findings.find((finding) => finding.id === selectedFindingId) ?? null;
  const statusByNode = new Map(nodeStatuses.map((nodeStatus) => [nodeStatus.nodeId, nodeStatus.status]));
  const visualNodes = nodes.map((node) => ({
    ...node,
    data: { ...node.data, status: statusByNode.get(node.id) },
  }));
  const visualEdges = edges.map((edge) => ({
    ...edge,
    animated: agentMessages.some((message) => (
      message.sourceNodeId === edge.source && message.targetNodeId === edge.target
    )),
    className: selectedEdgeId === edge.id ? "edge-selected" : undefined,
  }));
  const selectedEdgeMessages = selectedEdge ? agentMessages.filter((message) => (
    message.sourceNodeId === selectedEdge.source && message.targetNodeId === selectedEdge.target
  )) : [];
  const selectedNodeMessages = selectedNode ? agentMessages.filter((message) => (
    message.sourceNodeId === selectedNode.id || message.targetNodeId === selectedNode.id
  )) : [];
  const selectedNodeInvocations = selectedNode ? aiNodeInvocations.filter((invocation) => (
    invocation.nodeId === selectedNode.id
  )) : [];

  async function refreshRunDetails(runId: string) {
    try {
      const [nextAudit, nextStatuses, nextMessages, nextInvocations, nextFindings] = await Promise.all([
        request<AuditEvent[]>(`/api/runs/${runId}/audit`),
        request<NodeStatus[]>(`/api/runs/${runId}/node-statuses`),
        request<AgentMessage[]>(`/api/runs/${runId}/agent-messages`),
        request<AiNodeInvocation[]>(`/api/runs/${runId}/ai-node-invocations`),
        request<Finding[]>(`/api/runs/${runId}/findings`),
      ]);
      setAudit(nextAudit);
      setNodeStatuses(nextStatuses);
      setAgentMessages(nextMessages);
      setAiNodeInvocations(nextInvocations);
      setFindings(nextFindings);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to refresh run details");
    }
  }

  useEffect(() => {
    if (!run) return undefined;
    void refreshRunDetails(run.id);
    const intervalId = window.setInterval(() => void refreshRunDetails(run.id), 2000);
    return () => window.clearInterval(intervalId);
  }, [run]);

  const onConnect: OnConnect = (connection: Connection) => {
    if (!connection.source || !connection.target || connection.source === connection.target) return;
    setEdges((currentEdges) => addEdge({ ...connection, id: crypto.randomUUID() }, currentEdges));
  };

  function onDragStart(event: DragEvent<HTMLButtonElement>, kind: NodeKind) {
    event.dataTransfer.setData("application/adaptive-workflow-node", kind);
    event.dataTransfer.effectAllowed = "move";
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    const kind = event.dataTransfer.getData("application/adaptive-workflow-node") as NodeKind;
    const paletteItem = palette.find((item) => item.kind === kind);
    if (!reactFlow || !paletteItem) return;
    const position = reactFlow.screenToFlowPosition({ x: event.clientX, y: event.clientY });
    const newNode: WorkflowNode = {
      id: crypto.randomUUID(),
      type: "security",
      position,
      data: { kind, label: paletteItem.label, config: {} },
    };
    setNodes((currentNodes) => [...currentNodes, newNode]);
    setSelectedNodeId(newNode.id);
  }

  function updateSelectedNodeLabel(label: string) {
    if (!selectedNode) return;
    setNodes((currentNodes) => currentNodes.map((node) => (
      node.id === selectedNode.id ? { ...node, data: { ...node.data, label } } : node
    )));
  }

  function updateSelectedNodeTarget(target: string) {
    if (!selectedNode) return;
    setNodes((currentNodes) => currentNodes.map((node) => (
      node.id === selectedNode.id
        ? { ...node, data: { ...node.data, config: { ...node.data.config, target } } }
        : node
    )));
  }

  function updateSelectedNodeSshTarget(sshTarget: string) {
    if (!selectedNode) return;
    setNodes((currentNodes) => currentNodes.map((node) => (
      node.id === selectedNode.id
        ? { ...node, data: { ...node.data, config: { ...node.data.config, sshTarget } } }
        : node
    )));
  }

  function updateSelectedNodeExecutionSetting(key: string, value: string | undefined) {
    if (!selectedNode) return;
    setNodes((currentNodes) => currentNodes.map((node) => {
      if (node.id !== selectedNode.id) return node;
      const config = { ...node.data.config };
      if (value === undefined) {
        delete config[key];
      } else {
        config[key] = value;
      }
      return { ...node, data: { ...node.data, config } };
    }));
  }

  async function createFlow(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    try {
      const created = await request<CrystalFlow>("/api/crystal-flows", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: flowName }),
      });
      openFlow(created);
      setSavedFlows((flows) => [created, ...flows]);
      setRun(null);
      setAudit([]);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to create Crystal Flow");
    }
  }

  async function provisionReferenceCatalog() {
    setError(null);
    try {
      const catalog = await request<ReferenceCatalog>("/api/reference-catalog", { method: "POST" });
      const [benchmarkFlow, flows] = await Promise.all([
        request<CrystalFlow>(`/api/crystal-flows/${catalog.benchmarkFlowId}`),
        request<CrystalFlow[]>("/api/crystal-flows"),
      ]);
      setSavedFlows(flows);
      openFlow(benchmarkFlow);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to provision the reference catalog");
    }
  }

  function openFlow(selectedFlow: CrystalFlow, updatePath = true) {
    setFlow(selectedFlow);
    setNodes(selectedFlow.nodes.map(toCanvasNode));
    setEdges(selectedFlow.edges.map(toCanvasEdge));
    setSelectedNodeId(null);
    setSelectedEdgeId(null);
    setSelectedFindingId(null);
    setRun(null);
    setAudit([]);
    setNodeStatuses([]);
    setAgentMessages([]);
    setAiNodeInvocations([]);
    setFindings([]);
    if (updatePath) {
      navigate(`/workflows/${selectedFlow.id}`);
    }
  }

  async function saveFlow() {
    if (!flow) return;
    setError(null);
    try {
      const saved = await request<CrystalFlow>(`/api/crystal-flows/${flow.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          nodes: nodes.map((node) => ({
            id: node.id,
            type: node.data.kind,
            label: node.data.label,
            position: node.position,
            config: node.data.config,
          })),
          edges: edges.map((edge) => ({ id: edge.id, source: edge.source, target: edge.target })),
        }),
      });
      openFlow(saved);
      setSavedFlows((flows) => flows.map((savedFlow) => (
        savedFlow.id === saved.id ? saved : savedFlow
      )));
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to save Crystal Flow");
    }
  }

  async function deleteFlow() {
    if (!flow || !window.confirm(`Delete "${flow.name}" and all of its run records? This cannot be undone.`)) {
      return;
    }
    setError(null);
    try {
      await request<void>(`/api/crystal-flows/${flow.id}`, { method: "DELETE" });
      setSavedFlows((flows) => flows.filter((savedFlow) => savedFlow.id !== flow.id));
      setFlow(null);
      setNodes([]);
      setEdges([]);
      setSelectedNodeId(null);
      setSelectedEdgeId(null);
      setSelectedFindingId(null);
      setRun(null);
      setAudit([]);
      setNodeStatuses([]);
      setAgentMessages([]);
      setAiNodeInvocations([]);
      setFindings([]);
      navigate("/workflows");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to delete Crystal Flow");
    }
  }

  function deleteSelectedItem() {
    if (selectedNode) {
      const nextEdges = edges.filter((edge) => (
        edge.source !== selectedNode.id && edge.target !== selectedNode.id
      ));
      const nextNodes = nodes.filter((node) => node.id !== selectedNode.id);
      setEdges(nextEdges);
      setNodes(keepValidBranches(nextNodes, nextEdges));
      setSelectedNodeId(null);
      return;
    }
    if (selectedEdge) {
      const nextEdges = edges.filter((edge) => edge.id !== selectedEdge.id);
      setEdges(nextEdges);
      setNodes((currentNodes) => keepValidBranches(currentNodes, nextEdges));
      setSelectedEdgeId(null);
    }
  }

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      const target = event.target;
      if (
        (event.key !== "Delete" && event.key !== "Backspace")
        || target instanceof HTMLInputElement
        || target instanceof HTMLTextAreaElement
        || !(selectedNodeId || selectedEdgeId)
      ) {
        return;
      }
      event.preventDefault();
      deleteSelectedItem();
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [selectedNodeId, selectedEdgeId, nodes, edges]);

  async function startRun() {
    if (!flow) return;
    setError(null);
    try {
      const started = await request<WorkflowRun>(`/api/crystal-flows/${flow.id}/runs`, {
        method: "POST",
      });
      setRun(started);
      await refreshRunDetails(started.id);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to start run");
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><span /></div>
          <div><strong>Crystal Flow</strong><small>Security Orchestration</small></div>
        </div>

        <nav className="primary-nav" aria-label="Primary navigation">
          <a className={`nav-item ${page === "workflows" ? "is-active" : ""}`} href="/workflows" onClick={(event) => { event.preventDefault(); navigate("/workflows"); }}><span className="nav-icon">⌘</span>Workflow Studio</a>
          <a className={`nav-item ${page === "ctf" ? "is-active" : ""}`} href="/ctf-setup" onClick={(event) => { event.preventDefault(); navigate("/ctf-setup"); }}><span className="nav-icon">＋</span>CTF Setup</a>
          <a className={`nav-item ${page === "runs" ? "is-active" : ""}`} href="/runs" onClick={(event) => { event.preventDefault(); navigate("/runs"); }}><span className="nav-icon">◫</span>Run History<span className="nav-count">{run ? 1 : 0}</span></a>
          <a className={`nav-item ${page === "findings" ? "is-active" : ""}`} href="/findings" onClick={(event) => { event.preventDefault(); navigate("/findings"); }}><span className="nav-icon">◇</span>Findings<span className="nav-count">{findings.length}</span></a>
          <a className={`nav-item ${page === "policy" ? "is-active" : ""}`} href="/policy" onClick={(event) => { event.preventDefault(); navigate("/policy"); }}><span className="nav-icon">✓</span>Policy &amp; Scope</a>
        </nav>

        <div className="sidebar-section">
          <div className="section-label"><span>CRYSTAL FLOWS</span><span>{savedFlows.length}</span></div>
          <form className="quick-create" onSubmit={createFlow}>
            <input
              aria-label="New Crystal Flow name"
              maxLength={120}
              onChange={(event) => setFlowName(event.target.value)}
              placeholder="New flow name"
              required
              value={flowName}
            />
            <button aria-label="Create Crystal Flow" className="icon-button" type="submit">+</button>
          </form>
          <div className="flow-list">
            {savedFlows.map((savedFlow) => (
              <a
                className={`flow-list-item ${flow?.id === savedFlow.id ? "is-current" : ""}`}
                href={`/workflows/${savedFlow.id}`}
                key={savedFlow.id}
                onClick={(event) => { event.preventDefault(); openFlow(savedFlow); }}
              >
                <span className="flow-indicator" />
                <span><strong>{savedFlow.name}</strong><small>Version {savedFlow.version}</small></span>
              </a>
            ))}
          </div>
        </div>

        <div className="sidebar-footer">
          <div className="system-status"><span className="pulse-dot" /><span><strong>Control plane online</strong><small>Single-Owner · localhost</small></span></div>
          <button className="owner-chip" type="button"><span>OW</span><span><strong>Owner workspace</strong><small>Full access</small></span><b>•••</b></button>
        </div>
      </aside>

      <section className="main-workspace">
        <header className="topbar">
          <div>
            <div className="breadcrumbs"><span>Workspace</span><b>/</b><span>{page === "workflows" ? flow?.name ?? "Overview" : pageTitle}</span></div>
            <h1>{page === "workflows" ? flow?.name ?? pageTitle : pageTitle}</h1>
          </div>
          <div className="topbar-actions">
            <div className="environment-pill"><span className="pulse-dot" />Authorized lab</div>
            <button
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
              className="theme-toggle"
              onClick={() => setTheme((current) => current === "dark" ? "light" : "dark")}
              title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
              type="button"
            >
              <span>{theme === "dark" ? "☀" : "☾"}</span>
              <span>{theme === "dark" ? "Light" : "Dark"}</span>
            </button>
            {page === "workflows" && flow && <button className="button danger" onClick={() => void deleteFlow()} type="button">Delete flow</button>}
            {page === "workflows" && flow && <button className="button secondary" onClick={saveFlow} type="button">Save version</button>}
            {page === "workflows" && flow && <button className="button primary" onClick={startRun} type="button"><span>▶</span>{run ? "Start new run" : "Start run"}</button>}
          </div>
        </header>

        {error && <div className="error-toast" role="alert"><strong>Action failed</strong><span>{error}</span><button onClick={() => setError(null)} type="button">×</button></div>}

        {page === "ctf" ? (
          <CtfSetupPage onCreated={(createdFlow) => {
            setSavedFlows((flows) => [createdFlow, ...flows.filter((item) => item.id !== createdFlow.id)]);
            openFlow(createdFlow);
          }} />
        ) : page === "runs" ? (
          <main className="section-page">
            <div className="page-intro"><span>EXECUTION OPERATIONS</span><h2>Run History</h2><p>Review the current execution state and its auditable events. Run data remains attached to its originating Crystal Flow.</p></div>
            <div className="page-card">
              <div className="page-card-heading"><span>RECENT RUN</span><b>{run ? "1 RECORD" : "NO RECORDS"}</b></div>
              {run ? <div className="run-record"><span className="pulse-dot" /><span><strong>{run.id}</strong><small>Flow {run.crystalFlowId}</small></span><span className={`status-pill status-${run.status}`}>{run.status}</span></div> : <p className="page-empty">Start a Workflow from the Studio to create an execution record.</p>}
            </div>
          </main>
        ) : page === "findings" ? (
          <main className="section-page">
            <div className="page-intro"><span>EVIDENCE &amp; PROVENANCE</span><h2>Findings</h2><p>Inspect findings generated by the active run, including supporting nodes, policy outcomes, tool logs, and evidence artifacts.</p></div>
            <div className="page-card">
              <div className="page-card-heading"><span>ACTIVE FINDINGS</span><b>{findings.length} RECORDS</b></div>
              {findings.length === 0 ? <p className="page-empty">No Findings have been recorded in the current session.</p> : <ul className="page-finding-list">{findings.map((finding) => <li key={finding.id}><strong>{finding.title}</strong><span>{finding.target}</span><small>{finding.provenance.evidenceArtifacts.length} evidence artifacts</small></li>)}</ul>}
            </div>
          </main>
        ) : page === "policy" ? (
          <main className="section-page">
            <div className="page-intro"><span>GOVERNANCE CONTROL PLANE</span><h2>Policy &amp; Scope</h2><p>Execution remains bounded by declared targets, workspaces, permissions, resource limits, and approved VM environments.</p></div>
            <div className="policy-grid">
              <section className="page-card"><div className="page-card-heading"><span>SSH EXECUTION</span><b>HOST MANAGED</b></div><h3>Kali VM alias</h3><code>export KALI_SSH_TARGET=codex-kali</code><p>The platform resolves Kali tasks through this host-approved SSH alias. A node’s SSH field records the intended destination but cannot authorize a new host.</p></section>
              <section className="page-card"><div className="page-card-heading"><span>ENFORCEMENT</span><b>ALWAYS ON</b></div><ul className="control-list"><li>Scope and target validation</li><li>Workspace isolation</li><li>Policy and approval checks</li><li>Rate limits and budgets</li><li>Complete audit recording</li></ul></section>
            </div>
          </main>
        ) : !flow ? (
          <main className="empty-workspace">
            <section className="welcome-card">
              <div className="welcome-kicker">ADAPTIVE SECURITY ORCHESTRATION</div>
              <h2>Design governed security workflows with confidence.</h2>
              <p>Compose approved agents, scope every action, and preserve a complete evidence trail from one operational workspace.</p>
              <div className="welcome-actions">
                <button className="button primary" onClick={() => void provisionReferenceCatalog()} type="button">Provision reference catalog</button>
                <span>Includes five Specialist Agents and a safe lab benchmark.</span>
              </div>
            </section>
            <div className="overview-grid">
              <article><span className="metric-icon cyan">⌘</span><strong>{savedFlows.length}</strong><small>Versioned flows</small></article>
              <article><span className="metric-icon green">✓</span><strong>5</strong><small>Safety controls</small></article>
              <article><span className="metric-icon amber">◇</span><strong>{findings.length}</strong><small>Evidence findings</small></article>
            </div>
          </main>
        ) : (
          <main className="studio-workspace">
            <div className="studio-toolbar">
              <div className="mode-tabs"><button className="is-active" type="button">Builder</button><button type="button">Run view</button></div>
              <div className="flow-meta"><span>v{flow.version}</span><span>{nodes.length} nodes</span><span>{edges.length} branches</span>{run && <span className="run-live"><i />RUN LIVE</span>}</div>
            </div>

            <div className="studio-grid">
              <aside className="palette-panel" aria-label="Approved Workflow Nodes">
                <div className="panel-heading"><span>NODE LIBRARY</span><button type="button">⌕</button></div>
                <p>Drag an approved capability onto the Canvas.</p>
                <div className="palette-list">
                  {palette.map((item) => (
                    <button draggable key={item.kind} onDragStart={(event) => onDragStart(event, item.kind)} type="button">
                      <span className={`node-glyph node-glyph--${item.kind}`}>{nodeKindLabels[item.kind].slice(0, 1)}</span>
                      <span><strong>{item.label}</strong><small>{nodeKindLabels[item.kind]}</small></span>
                      <b>⋮⋮</b>
                    </button>
                  ))}
                </div>
                <button className="catalog-button" onClick={() => void provisionReferenceCatalog()} type="button">+ Provision agent catalog</button>
              </aside>

              <section className="canvas-panel">
                <div className="canvas-toolbar">
                  <div><span className="canvas-state-dot" />Graph ready</div>
                  <div><span>Drag to pan</span><span>Scroll to zoom</span></div>
                </div>
                <div className="canvas" onDragOver={(event) => event.preventDefault()} onDrop={onDrop}>
                  <ReactFlow
                    edges={visualEdges}
                    fitView
                    nodeTypes={nodeTypes}
                    nodes={visualNodes}
                    onConnect={onConnect}
                    onEdgeClick={(_, edge) => { setSelectedEdgeId(edge.id); setSelectedNodeId(null); }}
                    onEdgesChange={(changes) => setEdges((current) => applyEdgeChanges(changes, current))}
                    onInit={setReactFlow}
                    onNodeClick={(_, node) => { setSelectedNodeId(node.id); setSelectedEdgeId(null); }}
                    onNodesChange={(changes) => setNodes((current) => applyNodeChanges(changes, current))}
                    onPaneClick={() => { setSelectedNodeId(null); setSelectedEdgeId(null); }}
                  >
                    <Background color="#26384a" gap={24} size={1} />
                    <MiniMap maskColor="rgba(7, 14, 23, .78)" nodeColor="#2ed3c6" pannable zoomable />
                    <Controls />
                  </ReactFlow>
                </div>
              </section>

              <aside className="inspector-panel" aria-label="Node and edge inspector">
                <div className="panel-heading"><span>INSPECTOR</span><span className="selection-type">{selectedNode ? "NODE" : selectedEdge ? "EDGE" : "NONE"}</span></div>
                {selectedNode ? (
                  <div className="inspector-content">
                    <div className="selected-identity"><span className={`node-glyph node-glyph--${selectedNode.data.kind}`}>{nodeKindLabels[selectedNode.data.kind].slice(0, 1)}</span><span><strong>{selectedNode.data.label}</strong><small>{nodeKindLabels[selectedNode.data.kind]} · {statusByNode.get(selectedNode.id) ?? "READY"}</small></span></div>
                    <label htmlFor="node-label">Display name</label>
                    <input id="node-label" onChange={(event) => updateSelectedNodeLabel(event.target.value)} value={selectedNode.data.label} />
                    <label htmlFor="node-target">Target or task detail</label>
                    <input id="node-target" onChange={(event) => updateSelectedNodeTarget(event.target.value)} placeholder="Declared task target" value={typeof selectedNode.data.config.target === "string" ? selectedNode.data.config.target : ""} />
                    <label htmlFor="node-ssh-target">SSH execution alias</label>
                    <input id="node-ssh-target" onChange={(event) => updateSelectedNodeSshTarget(event.target.value)} placeholder="codex-kali" value={typeof selectedNode.data.config.sshTarget === "string" ? selectedNode.data.config.sshTarget : ""} />
                    <p className="field-help">
                      {typeof selectedNode.data.config.sshTarget === "string" && selectedNode.data.config.sshTarget
                        ? <>Resolved command: <code>ssh {selectedNode.data.config.sshTarget}</code></>
                        : <>Example: <code>ssh codex-kali</code>. The host alias must also be approved in the execution environment.</>}
                    </p>
                    {selectedNode.data.kind !== "approval-gate" && (
                      <section className="execution-profile">
                        <div className="execution-profile-heading"><span>AI EXECUTION PROFILE</span><b>ISOLATED PER NODE</b></div>
                        <label htmlFor="node-model">Codex model</label>
                        <select
                          id="node-model"
                          onChange={(event) => updateSelectedNodeExecutionSetting("model", event.target.value === "session-default" ? undefined : event.target.value)}
                          value={typeof selectedNode.data.config.model === "string" ? selectedNode.data.config.model : "session-default"}
                        >
                          <option value="session-default">Session default</option>
                          <option value="gpt-5.6-sol">GPT-5.6 Sol — complex work</option>
                          <option value="gpt-5.6-terra">GPT-5.6 Terra — balanced</option>
                          <option value="gpt-5.6-luna">GPT-5.6 Luna — repeatable tasks</option>
                        </select>
                        <label htmlFor="node-reasoning-effort">Reasoning effort</label>
                        <select
                          id="node-reasoning-effort"
                          onChange={(event) => updateSelectedNodeExecutionSetting("reasoningEffort", event.target.value)}
                          value={typeof selectedNode.data.config.reasoningEffort === "string" ? selectedNode.data.config.reasoningEffort : "medium"}
                        >
                          <option value="low">Low — fastest</option>
                          <option value="medium">Medium — recommended</option>
                          <option value="high">High — deeper analysis</option>
                          <option value="xhigh">Extra high — hardest tasks</option>
                        </select>
                        <p className="field-help">Passed to the Codex app-server as per-turn <code>model</code> and <code>effort</code> overrides.</p>
                      </section>
                    )}
                    <div className="config-summary"><span><small>Status</small><strong>{statusByNode.get(selectedNode.id) ?? "Not started"}</strong></span><span><small>Messages</small><strong>{selectedNodeMessages.length}</strong></span><span><small>AI calls</small><strong>{selectedNodeInvocations.length}</strong></span></div>
                    <InspectionList label="Agent Messages" values={selectedNodeMessages.map((message) => `${message.trigger}: ${JSON.stringify(message.message)}`)} />
                    <InspectionList label="AI node activity" values={selectedNodeInvocations.map((invocation) => `${invocation.model ?? "session-default"} · ${invocation.reasoningEffort} · ${invocation.status}: ${JSON.stringify(invocation.output)}`)} />
                    <button className="delete-item-button" onClick={deleteSelectedItem} type="button">Delete node and connections</button>
                  </div>
                ) : selectedEdge ? (
                  <div className="inspector-content"><div className="edge-route"><span>{selectedEdge.source}</span><b>→</b><span>{selectedEdge.target}</span></div><InspectionList label="Data transfer" values={selectedEdgeMessages.map((message) => `${message.trigger}: ${JSON.stringify(message.message)}`)} /><button className="delete-item-button" onClick={deleteSelectedItem} type="button">Delete connection</button></div>
                ) : (
                  <div className="inspector-empty"><span>⌖</span><strong>Nothing selected</strong><p>Select a node or branch to inspect its configuration, messages, and execution history.</p></div>
                )}
              </aside>
            </div>

            {run && (
              <section className="operations-dock" aria-labelledby="execution-title">
                <div className="dock-header"><div><span className="pulse-dot" /><span><strong id="execution-title">Live execution</strong><small>{run.id.slice(0, 12)} · polling every 2 seconds</small></span></div><button onClick={() => void refreshRunDetails(run.id)} type="button">Refresh now</button></div>
                <div className="dock-grid">
                  <section><div className="dock-section-title"><span>NODE STATUS</span><b>{nodeStatuses.length}</b></div>{nodeStatuses.length === 0 ? <p className="empty-copy">Waiting for Workflow Node activity.</p> : <ul className="status-list">{nodeStatuses.map((item) => <li key={item.nodeId}><span>{item.nodeId}</span><span className={`status-pill status-${item.status}`}>{item.status}</span></li>)}</ul>}</section>
                  <section><div className="dock-section-title"><span>EXECUTION TRAIL</span><b>{audit.length}</b></div><ul className="audit-list">{audit.map((event, index) => <li key={`${event.eventType}-${index}`}><i />{event.eventType}</li>)}</ul></section>
                  <section><div className="dock-section-title"><span>FINDINGS</span><b>{findings.length}</b></div>{findings.length === 0 ? <p className="empty-copy">No Findings recorded.</p> : <ul className="finding-list">{findings.map((finding) => <li key={finding.id}><button className={selectedFindingId === finding.id ? "finding-selected" : ""} onClick={() => setSelectedFindingId(finding.id)} type="button">{finding.title}<small>{finding.target}</small></button></li>)}</ul>}</section>
                </div>
                {selectedFinding && <section className="finding-provenance" aria-label="Finding provenance"><div className="finding-title"><span>FINDING DETAIL</span><button onClick={() => setSelectedFindingId(null)} type="button">×</button></div><h3>{selectedFinding.title}</h3><p>{selectedFinding.target}</p><div className="provenance-grid"><InspectionList label="Supporting nodes" values={selectedFinding.provenance.nodeIds} /><InspectionList label="Agent Messages" values={selectedFinding.provenance.agentMessages.map((message) => `${message.sourceNodeId} · ${message.trigger}: ${JSON.stringify(message.message)}`)} /><InspectionList label="Tool calls & logs" values={selectedFinding.provenance.toolCalls.map((toolCall) => `${toolCall.status}: ${toolCall.stdout || toolCall.stderr || "No output"}`)} /><InspectionList label="Policy outcomes" values={selectedFinding.provenance.policyDecisions.map((decision) => `${decision.status}: ${decision.reason}`)} /><InspectionList label="Evidence artifacts" values={selectedFinding.provenance.evidenceArtifacts.map((artifact) => `${artifact.availability} · ${artifact.storage} · ${artifact.vmResidentPath ?? artifact.sha256}: ${artifact.summary}`)} /></div></section>}
              </section>
            )}
          </main>
        )}
      </section>
    </div>
  );
}
