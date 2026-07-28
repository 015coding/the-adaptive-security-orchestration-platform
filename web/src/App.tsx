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
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    request<CrystalFlow[]>("/api/crystal-flows")
      .then(setSavedFlows)
      .catch(() => setError("Unable to load saved Crystal Flows"));
  }, []);

  const selectedNode = nodes.find((node) => node.id === selectedNodeId) ?? null;

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

  function openFlow(selectedFlow: CrystalFlow) {
    setFlow(selectedFlow);
    setNodes(selectedFlow.nodes.map(toCanvasNode));
    setEdges(selectedFlow.edges.map(toCanvasEdge));
    setSelectedNodeId(null);
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
      setAudit(await request<AuditEvent[]>(`/api/runs/${started.id}/audit`));
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
                edges={edges}
                fitView
                nodes={nodes}
                onConnect={onConnect}
                onEdgesChange={(changes) => setEdges((current) => applyEdgeChanges(changes, current))}
                onInit={setReactFlow}
                onNodeClick={(_, node) => setSelectedNodeId(node.id)}
                onNodesChange={(changes) => setNodes((current) => applyNodeChanges(changes, current))}
              >
                <Background />
                <Controls />
              </ReactFlow>
            </div>
            <aside aria-label="Node configuration" className="node-config">
              <h3>Node configuration</h3>
              {selectedNode ? (
                <>
                  <p className="muted">{selectedNode.data.kind}</p>
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
                </>
              ) : <p className="muted">Select a node to configure it.</p>}
            </aside>
          </div>
        </section>
      )}

      {run && (
        <section className="panel" aria-labelledby="audit-title">
          <h2 id="audit-title">Run audit</h2>
          <p>Run {run.id} is {run.status}.</p>
          <ul>{audit.map((event) => <li key={event.eventType}>{event.eventType}</li>)}</ul>
        </section>
      )}

      {error && <p className="error" role="alert">{error}</p>}
    </main>
  );
}
