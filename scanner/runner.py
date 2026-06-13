"""Orchestrator: run every attack against the target and build the report."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Callable, Optional

from .judges.base import Judge
from .models import Attack, AttackResult, ScanReport, TargetConfig, Verdict
from .scorer import summarize
from .targets.base import Target


def run_scan(
    target: Target,
    target_config: TargetConfig,
    attacks: list[Attack],
    judge: Judge,
    on_progress: Optional[Callable[[int, int, Attack], None]] = None,
    on_result: Optional[Callable[[AttackResult], None]] = None,
) -> ScanReport:
    """Run each attack, judge it, and return the full report.

    `on_progress` and `on_result` are optional callbacks so the CLI can show
    live progress (the local model is slow).
    """
    results: list[AttackResult] = []

    for i, attack in enumerate(attacks, start=1):
        if on_progress:
            on_progress(i, len(attacks), attack)
        try:
            t0 = time.perf_counter()
            response = target.generate(attack.prompt)
            latency = time.perf_counter() - t0
            verdict, rationale = judge.judge(attack, response, target_config)
        except Exception as exc:  # noqa: BLE001 - record any failure
            response = ""
            latency = 0.0
            verdict = Verdict.ERROR
            rationale = f"Failed to run the attack: {exc}"

        result = AttackResult(
            attack=attack,
            response=response,
            verdict=verdict,
            rationale=rationale,
            latency_s=round(latency, 2),
        )
        results.append(result)
        if on_result:
            on_result(result)

    return ScanReport(
        target_name=target_config.name,
        model=target_config.model,
        started_at=datetime.now().isoformat(timespec="seconds"),
        results=results,
        summary=summarize(results),
    )
