"""Data models for the scanner (pydantic).

These typed classes are the "tokens" that travel through the pipeline: an attack
goes in, it is run against the target model, and a result comes out. pydantic
gives us automatic validation and (almost free) loading from YAML/JSON.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    """Outcome of an attack, as decided by the judge."""

    SUCCESS = "success"  # the attack worked: the model broke its own rules
    BLOCKED = "blocked"  # the model resisted (refused)
    PARTIAL = "partial"  # it answered, but it is unclear whether it fell for it
    ERROR = "error"      # technical failure (e.g. the target did not respond)


class DetectionType(str, Enum):
    """How the judge decides whether an attack succeeded."""

    MARKERS = "markers"          # success if any of the success_markers appears
    LEAK_SECRET = "leak_secret"  # success if any of the target's secrets leaks


class Attack(BaseModel):
    """A single attack from the library (loaded from YAML)."""

    id: str
    category: str
    technique: str
    severity: str = "medium"
    goal: str
    prompt: str
    detection: DetectionType = DetectionType.MARKERS
    success_markers: list[str] = Field(default_factory=list)


class TargetConfig(BaseModel):
    """Configuration of the target model: which model, with which system prompt,
    and which secrets it must protect."""

    name: str
    model: str
    system_prompt: str
    secrets: dict[str, str] = Field(default_factory=dict)


class AttackResult(BaseModel):
    """The outcome of running ONE attack against the target."""

    attack: Attack
    response: str
    verdict: Verdict
    rationale: str
    latency_s: float


class CategoryStat(BaseModel):
    """Verdict counts for one attack category."""

    category: str
    total: int = 0
    success: int = 0
    blocked: int = 0
    partial: int = 0
    error: int = 0


class ScanSummary(BaseModel):
    """Aggregated metrics for the whole scan."""

    total: int
    success: int
    blocked: int
    partial: int
    error: int
    attack_success_rate: float  # % of attacks that succeeded (higher = worse model)
    robustness_score: float     # % of attacks the model withstood
    by_category: list[CategoryStat]


class ScanReport(BaseModel):
    """The full report: target + every result + summary."""

    target_name: str
    model: str
    started_at: str
    results: list[AttackResult]
    summary: ScanSummary
