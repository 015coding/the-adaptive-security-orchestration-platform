from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from threading import Lock
from typing import Protocol
from uuid import UUID


@dataclass(frozen=True)
class CodexCliResult:
    output: dict[str, object]
    resource_units: int


class CodexCliTimeout(RuntimeError):
    """Raised when the live Codex CLI session exceeds a Node Timeout."""


class CodexCliError(RuntimeError):
    """Raised when the configured Codex CLI session is unavailable or malformed."""


class CodexAppServerSession:
    """Resume one Codex thread through the local app-server JSON-RPC protocol."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self._process: subprocess.Popen[str] | None = None
        self._request_id = 0

    def _start(self) -> None:
        codex = shutil.which("codex")
        if codex is None:
            raise CodexCliError("Codex CLI executable was not found on PATH")
        self._process = subprocess.Popen(
            [codex, "app-server", "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._request("initialize", {
            "clientInfo": {"name": "adaptive-security-orchestration", "title": "Crystal Flow", "version": "0.1.0"},
            "capabilities": {"experimentalApi": True},
        })
        self._notify("initialized", {})
        self._request("thread/resume", {"threadId": self.session_id})

    def _send(self, payload: dict[str, object]) -> None:
        if self._process is None or self._process.stdin is None:
            raise CodexCliError("Codex app-server session is not running")
        self._process.stdin.write(json.dumps(payload) + "\n")
        self._process.stdin.flush()

    def _notify(self, method: str, params: dict[str, object]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def _request(self, method: str, params: dict[str, object]) -> dict[str, object]:
        self._request_id += 1
        request_id = self._request_id
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        if self._process is None or self._process.stdout is None:
            raise CodexCliError("Codex app-server session is not running")
        while True:
            line = self._process.stdout.readline()
            if not line:
                raise CodexCliError("Codex app-server session closed unexpectedly")
            message = json.loads(line)
            if message.get("id") != request_id:
                continue
            if "error" in message:
                error = message["error"]
                detail = error.get("message", "Codex app-server request failed") if isinstance(error, dict) else str(error)
                raise CodexCliError(str(detail))
            return message.get("result", {})

    def execute(self, request: dict[str, object], timeout_seconds: int) -> CodexCliResult:
        if self._process is None:
            self._start()
        task = str(request.get("task", ""))
        task_input = request.get("input", {})
        prompt = f"{task}\n\nStructured input:\n{json.dumps(task_input, sort_keys=True)}"
        turn_params: dict[str, object] = {
            "threadId": self.session_id,
            "input": [{"type": "text", "text": prompt}],
        }
        if isinstance(request.get("model"), str) and request["model"]:
            turn_params["model"] = request["model"]
        if isinstance(request.get("reasoningEffort"), str):
            turn_params["effort"] = request["reasoningEffort"]
        turn = self._request("turn/start", turn_params)
        turn_id = turn.get("id") or turn.get("turnId")
        if self._process is None or self._process.stdout is None:
            raise CodexCliError("Codex app-server session is not running")
        deadline = __import__("time").monotonic() + timeout_seconds
        final_turn: dict[str, object] | None = None
        while __import__("time").monotonic() < deadline:
            line = self._process.stdout.readline()
            if not line:
                raise CodexCliError("Codex app-server session closed unexpectedly")
            message = json.loads(line)
            if message.get("method") != "turn/completed":
                continue
            candidate = message.get("params", {}).get("turn", {}) if isinstance(message.get("params"), dict) else {}
            if not isinstance(candidate, dict) or (turn_id and candidate.get("id") != turn_id):
                continue
            final_turn = candidate
            break
        if final_turn is None:
            raise CodexCliTimeout("Codex app-server turn exceeded Node Timeout")
        if final_turn.get("status") != "completed":
            error = final_turn.get("error", {})
            reason = error.get("message", "Codex turn did not complete") if isinstance(error, dict) else str(error)
            raise CodexCliError(str(reason))
        items = final_turn.get("items", [])
        messages = [item.get("text", "") for item in items if isinstance(item, dict) and item.get("type") == "agentMessage"]
        return CodexCliResult(
            output={"summary": messages[-1] if messages else "Codex turn completed", "sessionId": self.session_id},
            resource_units=0,
        )


class CodexCli(Protocol):
    def execute(self, request: dict[str, object], timeout_seconds: int) -> CodexCliResult: ...


class SubprocessCodexCli:
    """Bridge to a local program that speaks the structured live-session contract."""

    def __init__(self, command: str | None = None) -> None:
        self._command = command or os.environ.get("CODEX_SESSION_COMMAND", "")

    def configure_command(self, command: str) -> None:
        self._command = command.strip()

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
        except FileNotFoundError as error:
            raise CodexCliError(f"Configured Codex bridge was not found: {self._command}") from error
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

    def configure_command(self, command: str) -> None:
        try:
            UUID(command.strip())
        except ValueError:
            pass
        else:
            with self._lock:
                self._codex_cli = CodexAppServerSession(command.strip())
            return
        configure = getattr(self._codex_cli, "configure_command", None)
        if not callable(configure):
            raise CodexCliError("The configured Codex runtime does not support command configuration")
        with self._lock:
            configure(command)

    def execute(self, request: dict[str, object], timeout_seconds: int) -> CodexCliResult:
        with self._lock:
            return self._codex_cli.execute(request, timeout_seconds)
