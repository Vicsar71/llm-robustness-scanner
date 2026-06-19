"""Tests for the reporters (Markdown + HTML, single scan + comparison).

Pure logic: no Ollama and no network. These guard two things that matter — that
untrusted model output is HTML-escaped (the report must not be an XSS vector),
and that the comparison ranks models correctly.
"""

from scanner.html_reporter import render_comparison_html, render_html
from scanner.models import (
    Attack,
    AttackResult,
    ComparisonReport,
    ScanReport,
    Verdict,
)
from scanner.reporter import render_comparison_markdown
from scanner.scorer import summarize


def _result(verdict: Verdict, response: str = "", aid: str = "a1") -> AttackResult:
    atk = Attack(id=aid, category="prompt_injection", technique="t", goal="g", prompt="p")
    return AttackResult(
        attack=atk, response=response, verdict=verdict, rationale="r", latency_s=0.1
    )


def _report(model: str, results: list[AttackResult]) -> ScanReport:
    return ScanReport(
        target_name="ACME",
        model=model,
        started_at="2026-06-19T10:00:00",
        results=results,
        summary=summarize(results),
    )


def test_html_report_has_score_and_target():
    report = _report("llama3.1:8b", [_result(Verdict.BLOCKED)])
    html = render_html(report)
    assert "<!doctype html>" in html
    assert "ACME" in html
    assert "llama3.1:8b" in html
    assert "100" in html  # fully robust: one blocked attack


def test_html_report_escapes_untrusted_response():
    """A malicious model response must not inject live markup into the report."""
    payload = "<script>alert('xss')</script>"
    report = _report("m", [_result(Verdict.SUCCESS, response=payload)])
    html = render_html(report)
    assert "<script>alert" not in html          # raw tag must not survive
    assert "&lt;script&gt;" in html             # it appears escaped instead


def test_comparison_markdown_ranks_most_robust_first():
    weak = _report("weak", [_result(Verdict.SUCCESS), _result(Verdict.SUCCESS)])
    strong = _report("strong", [_result(Verdict.BLOCKED), _result(Verdict.BLOCKED)])
    comparison = ComparisonReport(
        target_name="ACME",
        started_at="2026-06-19T10:00:00",
        attacks_total=2,
        reports=[weak, strong],  # given weak-first on purpose
    )
    md = render_comparison_markdown(comparison)
    # The strong model must be listed before the weak one in the leaderboard.
    assert md.index("`strong`") < md.index("`weak`")


def test_comparison_html_includes_all_models():
    a = _report("alpha", [_result(Verdict.BLOCKED)])
    b = _report("beta", [_result(Verdict.SUCCESS)])
    comparison = ComparisonReport(
        target_name="ACME",
        started_at="2026-06-19T10:00:00",
        attacks_total=1,
        reports=[a, b],
    )
    html = render_comparison_html(comparison)
    assert "alpha" in html and "beta" in html
    assert "Leaderboard" in html
