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
# Values may be normal SSH config aliases:
export KALI_SSH_TARGET=codex-kali
export DEBIAN_SSH_TARGET=codex-debian
```

For example, `KALI_SSH_TARGET=codex-kali` makes the host runner connect with
`ssh codex-kali '<scope-derived workspace command>'`. Configure `codex-kali` in
the Owner host's `~/.ssh/config` and verify `ssh codex-kali` works before
starting a run.

The remote `assessment-runner` account must be restricted by the VM configuration to its assigned Run Workspace and approved network targets. The host API passes only the Scope-derived workspace and timeout to SSH; it does not grant the Owner host filesystem to VM tasks.

## Configure the Codex CLI Session Adapter

Set `CODEX_SESSION_COMMAND` to a local bridge client for the one currently running Codex CLI session. The bridge reads one structured JSON request from standard input and returns JSON with `output` and `resourceUnits` fields. The API serializes all AI-node requests through that bridge and records their result, timeout, and resource usage.

## Verify

```sh
uv run pytest
cd web && npm run build
```
