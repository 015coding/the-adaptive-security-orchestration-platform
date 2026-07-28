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
      <small>{data.status ?? "Ready"}</small>
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

export function App() {
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

  function openFlow(selectedFlow: CrystalFlow) {
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
          <button className="nav-item is-active" type="button"><span className="nav-icon">⌘</span>Workflow Studio</button>
          <button className="nav-item" type="button"><span className="nav-icon">◫</span>Run History<span className="nav-count">{run ? 1 : 0}</span></button>
          <button className="nav-item" type="button"><span className="nav-icon">◇</span>Findings<span className="nav-count">{findings.length}</span></button>
          <button className="nav-item" type="button"><span className="nav-icon">✓</span>Policy &amp; Scope</button>
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
              <button
                className={`flow-list-item ${flow?.id === savedFlow.id ? "is-current" : ""}`}
                key={savedFlow.id}
                onClick={() => openFlow(savedFlow)}
                type="button"
              >
                <span className="flow-indicator" />
                <span><strong>{savedFlow.name}</strong><small>Version {savedFlow.version}</small></span>
              </button>
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
            <div className="breadcrumbs"><span>Workspace</span><b>/</b><span>{flow?.name ?? "Overview"}</span></div>
            <h1>{flow?.name ?? "Workflow Studio"}</h1>
          </div>
          <div className="topbar-actions">
            <div className="environment-pill"><span className="pulse-dot" />Authorized lab</div>
            {flow && <button className="button secondary" onClick={saveFlow} type="button">Save version</button>}
            {flow && <button className="button primary" onClick={startRun} type="button"><span>▶</span>{run ? "Start new run" : "Start run"}</button>}
          </div>
        </header>

        {error && <div className="error-toast" role="alert"><strong>Action failed</strong><span>{error}</span><button onClick={() => setError(null)} type="button">×</button></div>}

        {!flow ? (
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
                    <div className="config-summary"><span><small>Status</small><strong>{statusByNode.get(selectedNode.id) ?? "Not started"}</strong></span><span><small>Messages</small><strong>{selectedNodeMessages.length}</strong></span><span><small>AI calls</small><strong>{selectedNodeInvocations.length}</strong></span></div>
                    <InspectionList label="Agent Messages" values={selectedNodeMessages.map((message) => `${message.trigger}: ${JSON.stringify(message.message)}`)} />
                    <InspectionList label="AI node activity" values={selectedNodeInvocations.map((invocation) => `${invocation.status}: ${JSON.stringify(invocation.output)}`)} />
                  </div>
                ) : selectedEdge ? (
                  <div className="inspector-content"><div className="edge-route"><span>{selectedEdge.source}</span><b>→</b><span>{selectedEdge.target}</span></div><InspectionList label="Data transfer" values={selectedEdgeMessages.map((message) => `${message.trigger}: ${JSON.stringify(message.message)}`)} /></div>
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
