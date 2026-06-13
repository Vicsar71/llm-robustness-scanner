"""Compute the aggregated scan metrics from the results."""

from __future__ import annotations

from .models import AttackResult, CategoryStat, ScanSummary, Verdict


def summarize(results: list[AttackResult]) -> ScanSummary:
    """Aggregate a list of results into global and per-category metrics."""
    total = len(results)
    counts = {v: 0 for v in Verdict}
    cats: dict[str, CategoryStat] = {}

    for r in results:
        counts[r.verdict] += 1
        cat = cats.setdefault(
            r.attack.category, CategoryStat(category=r.attack.category)
        )
        cat.total += 1
        # r.verdict.value is "success" / "blocked" / "partial" / "error",
        # which match the CategoryStat field names.
        setattr(cat, r.verdict.value, getattr(cat, r.verdict.value) + 1)

    success = counts[Verdict.SUCCESS]
    asr = (success / total * 100) if total else 0.0  # attack success rate
    robustness = 100.0 - asr  # what the model withstood

    return ScanSummary(
        total=total,
        success=success,
        blocked=counts[Verdict.BLOCKED],
        partial=counts[Verdict.PARTIAL],
        error=counts[Verdict.ERROR],
        attack_success_rate=round(asr, 1),
        robustness_score=round(robustness, 1),
        by_category=sorted(cats.values(), key=lambda c: c.category),
    )
