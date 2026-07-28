from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class VmCommandResult:
    exit_code: int
    stdout: str
    stderr: str


class VmRunnerError(RuntimeError):
    """Raised when a configured execution environment cannot run a task."""


class SshVmRunner:
    """Runs a task in a configured VM without granting host filesystem access."""

    def __init__(self, environments: dict[str, str]) -> None:
        self._environments = environments

    @classmethod
    def from_environment(cls) -> "SshVmRunner":
        return cls(
            {
                "kali": os.environ.get("KALI_SSH_TARGET", ""),
                "debian": os.environ.get("DEBIAN_SSH_TARGET", ""),
            }
        )

    def execute(
        self, *, environment: str, workspace: str, command: list[str], timeout_seconds: int
    ) -> VmCommandResult:
        ssh_target = self._environments.get(environment)
        if not ssh_target:
            raise VmRunnerError(f"{environment} execution environment is not configured")
        remote_command = "cd -- " + shlex.quote(workspace) + " && exec " + shlex.join(command)
        try:
            result = subprocess.run(
                ["ssh", ssh_target, remote_command],
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            return VmCommandResult(
                exit_code=124,
                stdout=error.stdout or "",
                stderr=error.stderr or "task exceeded Scope runtime limit",
            )
        return VmCommandResult(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
