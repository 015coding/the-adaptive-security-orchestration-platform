from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class ScopePolicyInput:
    targets: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    starts_at: datetime
    expires_at: datetime
    unattended_execution: bool
    authorized_lab_environment: bool


@dataclass(frozen=True)
class PolicyOutcome:
    status: str
    reason: str


class PolicyEngine:
    """Evaluates the baseline Scope rules at the policy enforcement boundary."""

    def evaluate(
        self, scope: ScopePolicyInput, *, target: str, action: str, now: datetime | None = None
    ) -> PolicyOutcome:
        evaluated_at = now or datetime.now(UTC)
        if evaluated_at < scope.starts_at:
            return PolicyOutcome("deny", "Scope Window has not started")
        if evaluated_at >= scope.expires_at:
            return PolicyOutcome("deny", "Scope Window has expired")
        if target not in scope.targets:
            return PolicyOutcome("deny", "target is outside Scope")
        if action not in scope.allowed_actions:
            return PolicyOutcome("deny", "action is not permitted by Scope")
        if action == "exploitation-attempt" and not scope.authorized_lab_environment:
            return PolicyOutcome("deny", "automated exploitation requires an Authorized Lab Environment")
        if action == "exploitation-attempt" and not scope.unattended_execution:
            return PolicyOutcome("approval-required", "Exploitation Attempt requires Approval")
        return PolicyOutcome("allow", "action is permitted by Scope")
