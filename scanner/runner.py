"""Orchestrator: run every attack against the target and build the report."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Callable, Optional

from .attacks.generator import ClaudeAttackGenerator
from .judges.base import Judge
from .models import (
    Attack,
    AttackResult,
    ComparisonReport,
    ScanReport,
    TargetConfig,
    Verdict,
)
from .scorer import summarize
from .targets.base import Target


def _run_one(
    target: Target,
    target_config: TargetConfig,
    attack: Attack,
    judge: Judge,
) -> AttackResult:
    """Run a single attack against the target and judge it.

    Any failure (target down, judge error) is captured as an ERROR verdict so one
    bad attack never aborts the whole scan.
    """
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

    return AttackResult(
        attack=attack,
        response=response,
        verdict=verdict,
        rationale=rationale,
        latency_s=round(latency, 2),
    )


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
        result = _run_one(target, target_config, attack, judge)
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


def run_adaptive_scan(
    target: Target,
    target_config: TargetConfig,
    attacks: list[Attack],
    judge: Judge,
    generator: ClaudeAttackGenerator,
    max_rounds: int = 2,
    on_progress: Optional[Callable[[int, int, Attack], None]] = None,
    on_result: Optional[Callable[[AttackResult], None]] = None,
    on_adapt: Optional[Callable[[Attack, int, Optional[Attack], Optional[str]], None]] = None,
) -> ScanReport:
    """Run each attack and, while the target keeps BLOCKING it, have Claude rewrite
    and retry it up to `max_rounds` times.

    Each attempt — the seed and every adaptation — is recorded as a normal
    `AttackResult`, so the report, scorer and reporters need no changes: an
    escalated chain simply produces more results. A chain stops as soon as the
    target stops blocking (success, partial or error) or the round budget runs
    out. `on_adapt(blocked_attack, round, new_attack, error)` fires per
    adaptation: `new_attack` is the rewritten attack, or `error` is set if the
    attacker API call failed (in which case that chain just stops).
    """
    results: list[AttackResult] = []

    for i, seed in enumerate(attacks, start=1):
        if on_progress:
            on_progress(i, len(attacks), seed)

        current = seed
        for round_no in range(max_rounds + 1):  # round 0 = the seed itself
            result = _run_one(target, target_config, current, judge)
            results.append(result)
            if on_result:
                on_result(result)

            # Only keep escalating while the model is actively resisting.
            if result.verdict is not Verdict.BLOCKED or round_no >= max_rounds:
                break

            try:
                nxt = generator.adapt(current, result.response, target_config, round_no + 1)
            except Exception as exc:  # noqa: BLE001 - can't adapt -> stop this chain
                if on_adapt:
                    on_adapt(current, round_no + 1, None, str(exc))
                break

            if on_adapt:
                on_adapt(current, round_no + 1, nxt, None)
            current = nxt

    return ScanReport(
        target_name=target_config.name,
        model=target_config.model,
        started_at=datetime.now().isoformat(timespec="seconds"),
        results=results,
        summary=summarize(results),
    )


def run_comparison(
    models: list[str],
    target_config: TargetConfig,
    attacks: list[Attack],
    judge: Judge,
    target_factory: Callable[[str], Target],
    on_model: Optional[Callable[[int, int, str], None]] = None,
    on_progress: Optional[Callable[[int, int, Attack], None]] = None,
    on_result: Optional[Callable[[AttackResult], None]] = None,
) -> ComparisonReport:
    """Run the same attack suite + system prompt against several models.

    `target_factory` builds a Target for a given model name, so the runner stays
    decoupled from any concrete adapter (the CLI passes a factory that creates
    Ollama targets). `on_model` fires once per model before its scan starts.
    """
    reports: list[ScanReport] = []

    for i, model in enumerate(models, start=1):
        if on_model:
            on_model(i, len(models), model)
        # Same target (name, system prompt, secrets) but swap the model so each
        # report records which model it tested.
        cfg = target_config.model_copy(update={"model": model})
        target = target_factory(model)
        report = run_scan(target, cfg, attacks, judge, on_progress, on_result)
        reports.append(report)

    return ComparisonReport(
        target_name=target_config.name,
        started_at=datetime.now().isoformat(timespec="seconds"),
        attacks_total=len(attacks),
        reports=reports,
    )
