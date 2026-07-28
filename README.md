# Adaptive Security Orchestration Platform

The MVP is a self-hosted, single-Owner platform for governed cybersecurity assessment workflows.

## Run the platform shell

Start the host API from the repository root:

```sh
uv run uvicorn app.main:app --reload
```

In a second terminal, start the Owner UI:

```sh
cd web
npm install
npm run dev
```

Open the URL printed by Vite. The UI creates a blank Crystal Flow and starts a host-audited run. The visual Workflow Canvas, Scope, Policy Engine, and VM execution are delivered in subsequent tickets.

## Verify

```sh
uv run pytest
cd web && npm run build
```
