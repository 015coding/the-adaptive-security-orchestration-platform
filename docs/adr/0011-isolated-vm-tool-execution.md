# Isolated VM tool execution

Codex CLI and the orchestration service may run on the Owner's host, while security and forensic tools execute in a dedicated Kali VM and browser automation in a separate Debian VM. Every run receives a Run Workspace and Scope-derived permissions; runs receive no default access to the host filesystem, other workspaces, or undeclared network targets, including during Unattended Execution.
