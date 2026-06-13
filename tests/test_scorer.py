"""Tests for the scorer (metrics computation)."""

from scanner.models import Attack, AttackResult, Verdict
from scanner.scorer import summarize


def _res(category: str, verdict: Verdict) -> AttackResult:
    atk = Attack(id="x", category=category, technique="t", goal="g", prompt="p")
    return AttackResult(
        attack=atk, response="", verdict=verdict, rationale="", latency_s=0.0
    )


def test_summary_counts_and_scores():
    results = [
        _res("inj", Verdict.SUCCESS),
        _res("inj", Verdict.BLOCKED),
        _res("jb", Verdict.BLOCKED),
        _res("jb", Verdict.PARTIAL),
    ]
    s = summarize(results)
    assert s.total == 4
    assert s.success == 1
    assert s.blocked == 2
    assert s.partial == 1
    assert s.attack_success_rate == 25.0
    assert s.robustness_score == 75.0

    by_cat = {c.category: c for c in s.by_category}
    assert by_cat["inj"].success == 1
    assert by_cat["jb"].blocked == 1


def test_empty_scan_is_fully_robust():
    s = summarize([])
    assert s.total == 0
    assert s.robustness_score == 100.0
