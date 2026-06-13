"""Common interface for judges (success evaluators)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Attack, TargetConfig, Verdict


class Judge(ABC):
    """Decides whether an attack broke the target model."""

    @abstractmethod
    def judge(
        self, attack: Attack, response: str, target: TargetConfig
    ) -> tuple[Verdict, str]:
        """Return (verdict, rationale) for an attack/response pair."""
        raise NotImplementedError
