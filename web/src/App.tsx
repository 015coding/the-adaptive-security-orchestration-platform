import { DragEvent, FormEvent, useEffect, useState } from "react";
import {
  addEdge,
  applyEdgeChanges,
  applyNodeChanges,
  Background,
  Connection,
  Controls,
  Edge,
  Node,
  OnConnect,
  ReactFlow,
  ReactFlowInstance,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

type NodeKind = "recon-agent" | "verification-step" | "approval-gate" | "custom-agent";

type WorkflowNodeData = {
  kind: NodeKind;
  label: string;
  config: Record<string, unknown>;
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
    type: "default",
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
    className: statusByNode.has(node.id) ? `node-status-${statusByNode.get(node.id)}` : undefined,
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
      type: "default",
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
    <main>
      <header>
        <p className="eyebrow">Single-Owner MVP</p>
        <h1>Adaptive Security Orchestration</h1>
        <p>Compose a versioned Crystal Flow, then start a host-audited run.</p>
      </header>

      <section className="panel" aria-labelledby="create-flow-title">
        <h2 id="create-flow-title">New Crystal Flow</h2>
        <form onSubmit={createFlow}>
          <label htmlFor="flow-name">Flow name</label>
          <div className="actions">
            <input
              id="flow-name"
              minLength={1}
              maxLength={120}
              onChange={(event) => setFlowName(event.target.value)}
              required
              value={flowName}
            />
            <button type="submit">Create flow</button>
          </div>
        </form>
        <div className="actions">
          <button onClick={() => void provisionReferenceCatalog()} type="button">Provision reference catalog</button>
          <p className="muted">Creates the five built-in Specialist Agents and the authorized-lab safety benchmark.</p>
        </div>
      </section>

      <section className="panel" aria-labelledby="saved-flow-title">
        <h2 id="saved-flow-title">Saved Crystal Flows</h2>
        {savedFlows.length === 0 ? <p className="muted">No Crystal Flows yet.</p> : (
          <ul className="saved-flows">
            {savedFlows.map((savedFlow) => (
              <li key={savedFlow.id}>
                <span>{savedFlow.name} · version {savedFlow.version}</span>
                <button onClick={() => openFlow(savedFlow)} type="button">Open</button>
              </li>
            ))}
          </ul>
        )}
      </section>

      {flow && (
        <section className="panel" aria-labelledby="canvas-title">
          <div className="canvas-heading">
            <div>
              <h2 id="canvas-title">{flow.name}</h2>
              <p>Version {flow.version} · drag approved nodes, connect branches, then save a new version.</p>
            </div>
            <div className="actions">
              <button onClick={saveFlow} type="button">Save new version</button>
              <button onClick={startRun} type="button">Start run</button>
            </div>
          </div>
          <div className="workflow-editor">
            <aside aria-label="Approved Workflow Nodes" className="node-palette">
              <h3>Approved nodes</h3>
              {palette.map((item) => (
                <button
                  draggable
                  key={item.kind}
                  onDragStart={(event) => onDragStart(event, item.kind)}
                  type="button"
                >
                  {item.label}
                </button>
              ))}
            </aside>
            <div className="canvas" onDragOver={(event) => event.preventDefault()} onDrop={onDrop}>
              <ReactFlow
                edges={visualEdges}
                fitView
                nodes={visualNodes}
                onConnect={onConnect}
                onEdgeClick={(_, edge) => {
                  setSelectedEdgeId(edge.id);
                  setSelectedNodeId(null);
                }}
                onEdgesChange={(changes) => setEdges((current) => applyEdgeChanges(changes, current))}
                onInit={setReactFlow}
                onNodeClick={(_, node) => {
                  setSelectedNodeId(node.id);
                  setSelectedEdgeId(null);
                }}
                onNodesChange={(changes) => setNodes((current) => applyNodeChanges(changes, current))}
              >
                <Background />
                <Controls />
              </ReactFlow>
            </div>
            <aside aria-label="Node and edge inspector" className="node-config">
              <h3>Node &amp; edge inspector</h3>
              {selectedNode ? (
                <>
                  <p className="muted">{selectedNode.data.kind} · {statusByNode.get(selectedNode.id) ?? "not started"}</p>
                  <label htmlFor="node-label">Label</label>
                  <input
                    id="node-label"
                    onChange={(event) => updateSelectedNodeLabel(event.target.value)}
                    value={selectedNode.data.label}
                  />
                  <label htmlFor="node-target">Target or task detail</label>
                  <input
                    id="node-target"
                    onChange={(event) => updateSelectedNodeTarget(event.target.value)}
                    value={typeof selectedNode.data.config.target === "string" ? selectedNode.data.config.target : ""}
                  />
                  <InspectionList label="Agent Messages" values={selectedNodeMessages.map((message) => `${message.trigger}: ${JSON.stringify(message.message)}`)} />
                  <InspectionList label="AI node activity" values={selectedNodeInvocations.map((invocation) => `${invocation.status}: ${JSON.stringify(invocation.output)}`)} />
                </>
              ) : selectedEdge ? (
                <>
                  <p className="muted">{selectedEdge.source} → {selectedEdge.target}</p>
                  <InspectionList label="Data transfer" values={selectedEdgeMessages.map((message) => `${message.trigger}: ${JSON.stringify(message.message)}`)} />
                </>
              ) : <p className="muted">Select a node or edge to inspect it.</p>}
            </aside>
          </div>
        </section>
      )}

      {run && (
        <section className="panel" aria-labelledby="execution-title">
          <div className="canvas-heading">
            <div>
              <h2 id="execution-title">Live execution &amp; audit</h2>
              <p>Run {run.id} is {run.status}. Status and data transfer refresh every two seconds.</p>
            </div>
            <button onClick={() => void refreshRunDetails(run.id)} type="button">Refresh</button>
          </div>
          <div className="execution-grid">
            <section>
              <h3>Node status</h3>
              {nodeStatuses.length === 0 ? <p className="muted">No Workflow Node activity yet.</p> : (
                <ul className="status-list">{nodeStatuses.map((nodeStatus) => (
                  <li key={nodeStatus.nodeId}><span>{nodeStatus.nodeId}</span><span className={`status-pill status-${nodeStatus.status}`}>{nodeStatus.status}</span></li>
                ))}</ul>
              )}
              <h3>Execution Trail</h3>
              <ul className="audit-list">{audit.map((event, index) => <li key={`${event.eventType}-${index}`}>{event.eventType}</li>)}</ul>
            </section>
            <section>
              <h3>Findings</h3>
              {findings.length === 0 ? <p className="muted">No Findings recorded for this run.</p> : (
                <ul className="finding-list">{findings.map((finding) => (
                  <li key={finding.id}>
                    <button className={selectedFindingId === finding.id ? "finding-selected" : ""} onClick={() => setSelectedFindingId(finding.id)} type="button">
                      {finding.title}
                    </button>
                  </li>
                ))}</ul>
              )}
              {selectedFinding && (
                <section className="finding-provenance" aria-label="Finding provenance">
                  <h4>{selectedFinding.title}</h4>
                  <p className="muted">{selectedFinding.target}</p>
                  <InspectionList label="Supporting Workflow Nodes" values={selectedFinding.provenance.nodeIds} />
                  <InspectionList label="Agent Messages" values={selectedFinding.provenance.agentMessages.map((message) => `${message.sourceNodeId} · ${message.trigger}: ${JSON.stringify(message.message)}`)} />
                  <InspectionList label="Tool calls and logs" values={selectedFinding.provenance.toolCalls.map((toolCall) => `${toolCall.status}: ${toolCall.stdout || toolCall.stderr || "No output"}`)} />
                  <InspectionList label="Policy outcomes and Approvals" values={selectedFinding.provenance.policyDecisions.map((decision) => `${decision.status}: ${decision.reason}`)} />
                  <InspectionList label="Evidence artifacts" values={selectedFinding.provenance.evidenceArtifacts.map((artifact) => `${artifact.availability} · ${artifact.storage} · ${artifact.vmResidentPath ?? artifact.sha256}: ${artifact.summary}`)} />
                </section>
              )}
            </section>
          </div>
        </section>
      )}

      {error && <p className="error" role="alert">{error}</p>}
    </main>
  );
}
