from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from threading import Lock
from typing import Protocol


@dataclass(frozen=True)
class CodexCliResult:
    output: dict[str, object]
    resource_units: int


class CodexCliTimeout(RuntimeError):
    """Raised when the live Codex CLI session exceeds a Node Timeout."""


class CodexCliError(RuntimeError):
    """Raised when the configured Codex CLI session is unavailable or malformed."""


class CodexCli(Protocol):
    def execute(self, request: dict[str, object], timeout_seconds: int) -> CodexCliResult: ...


class SubprocessCodexCli:
    """Bridge to a local program that speaks the structured live-session contract."""

    def __init__(self, command: str | None = None) -> None:
        self._command = command or os.environ.get("CODEX_SESSION_COMMAND", "")

    def execute(self, request: dict[str, object], timeout_seconds: int) -> CodexCliResult:
        if not self._command:
            raise CodexCliError(
                "Codex CLI session is not configured; set CODEX_SESSION_COMMAND to the local JSON bridge command"
            )
        try:
            result = subprocess.run(
                shlex.split(self._command),
                input=json.dumps(request),
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            raise CodexCliTimeout("Codex CLI session exceeded Node Timeout") from error
        if result.returncode != 0:
            raise CodexCliError(result.stderr.strip() or "Codex CLI session failed")
        try:
            payload = json.loads(result.stdout)
            return CodexCliResult(output=payload["output"], resource_units=payload["resourceUnits"])
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise CodexCliError("Codex CLI session returned an invalid structured result") from error


class SessionAdapter:
    """Serializes all AI-powered Workflow Nodes through one live Codex CLI session."""

    def __init__(self, codex_cli: CodexCli) -> None:
        self._codex_cli = codex_cli
        self._lock = Lock()

    def execute(self, request: dict[str, object], timeout_seconds: int) -> CodexCliResult:
        with self._lock:
            return self._codex_cli.execute(request, timeout_seconds)
