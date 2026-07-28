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

Open the URL printed by Vite. The UI creates a Crystal Flow, edits its Workflow Canvas, saves immutable graph versions, and starts a host-audited run.

## Configure isolated VM execution

Set the SSH targets for the dedicated, restricted VM accounts before starting the API:

```sh
export KALI_SSH_TARGET=assessment-runner@kali-vm
export DEBIAN_SSH_TARGET=assessment-runner@debian-vm
```

The remote `assessment-runner` account must be restricted by the VM configuration to its assigned Run Workspace and approved network targets. The host API passes only the Scope-derived workspace and timeout to SSH; it does not grant the Owner host filesystem to VM tasks.

## Verify

```sh
uv run pytest
cd web && npm run build
```
