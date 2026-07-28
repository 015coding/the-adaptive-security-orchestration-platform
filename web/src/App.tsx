import { FormEvent, useEffect, useState } from "react";

type CrystalFlow = {
  id: string;
  name: string;
  version: number;
  nodes: object[];
  edges: object[];
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

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  if (!response.ok) {
    throw new Error(`Request failed with ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export function App() {
  const [flowName, setFlowName] = useState("");
  const [flow, setFlow] = useState<CrystalFlow | null>(null);
  const [savedFlows, setSavedFlows] = useState<CrystalFlow[]>([]);
  const [run, setRun] = useState<WorkflowRun | null>(null);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    request<CrystalFlow[]>("/api/crystal-flows")
      .then(setSavedFlows)
      .catch(() => setError("Unable to load saved Crystal Flows"));
  }, []);

  async function createFlow(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    try {
      const created = await request<CrystalFlow>("/api/crystal-flows", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: flowName }),
      });
      setFlow(created);
      setSavedFlows((flows) => [created, ...flows]);
      setRun(null);
      setAudit([]);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to create Crystal Flow");
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
        <p>Create a Crystal Flow, then start a host-audited run.</p>
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
            <button type="submit">Create blank flow</button>
          </div>
        </form>
      </section>

      <section className="panel" aria-labelledby="saved-flow-title">
        <h2 id="saved-flow-title">Saved Crystal Flows</h2>
        {savedFlows.length === 0 ? (
          <p className="muted">No Crystal Flows have been created yet.</p>
        ) : (
          <ul className="saved-flows">
            {savedFlows.map((savedFlow) => (
              <li key={savedFlow.id}>
                <span>{savedFlow.name} · version {savedFlow.version}</span>
                <button onClick={() => setFlow(savedFlow)} type="button">Open</button>
              </li>
            ))}
          </ul>
        )}
      </section>

      {flow && (
        <section className="panel" aria-labelledby="flow-title">
          <h2 id="flow-title">{flow.name}</h2>
          <p>Version {flow.version} · {flow.nodes.length} nodes · {flow.edges.length} edges</p>
          <p className="muted">Visual node authoring arrives with the Workflow Canvas ticket.</p>
          <button onClick={startRun} type="button">Start host-audited run</button>
        </section>
      )}

      {run && (
        <section className="panel" aria-labelledby="audit-title">
          <h2 id="audit-title">Run audit</h2>
          <p>Run {run.id} is {run.status}.</p>
          <ul>
            {audit.map((event) => <li key={event.eventType}>{event.eventType}</li>)}
          </ul>
        </section>
      )}

      {error && <p className="error" role="alert">{error}</p>}
    </main>
  );
}
