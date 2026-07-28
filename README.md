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

SSH targets can be configured from `/ctf-setup`. Environment variables remain
available as optional bootstrap defaults:

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

## Configure a CTF challenge from the UI

Open `/ctf-setup` to configure the Instance target, relative Challenge File
Path, VM Workspace, Kali or Debian SSH alias, Scope Window, resource limits,
exploitation permission, Human Approval Bypass, model, and reasoning effort.
Submitting the form persists and audits the SSH environment, creates the
isolated VM Workspace through SSH, adds both the Instance and file path to the
Scope, and creates a versioned Crystal Flow with a File Analysis Node.

Challenge files are intentionally not uploaded by this page. Copy them to the
declared VM Workspace path separately and keep large or raw files VM-resident.

The Workflow Node Library also includes standard `Start Node`, `Resolve / Worker`,
and `Exit Node` types. New CTF Flows include Start and Exit automatically; the
Worker type is available for manual drag-and-drop orchestration.

## Configure the Codex CLI Session Adapter

Set `CODEX_SESSION_COMMAND` to a local bridge client for the one currently running Codex CLI session. The bridge reads one structured JSON request from standard input and returns JSON with `output` and `resourceUnits` fields. The API serializes all AI-node requests through that bridge and records their result, timeout, and resource usage.

Each AI-capable Workflow Node can select a Codex model and reasoning effort.
The bridge request contains `model` and `reasoningEffort`; map these to the
Codex app-server `turn/start` fields `model` and `effort`. Selecting “Session
default” sends a null model so the active Codex configuration remains in
control. The selected values are also stored with the AI Node Invocation for
audit review.

Current picker choices are `gpt-5.6-sol`, `gpt-5.6-terra`, and
`gpt-5.6-luna`. Availability still depends on the models accessible to the
Owner's authenticated Codex CLI session.

## Verify

```sh
uv run pytest
cd web && npm run build
```
