"""Render the Markdown report from a ScanReport."""

from __future__ import annotations

from .models import ComparisonReport, ScanReport, Verdict

_VERDICT_LABEL = {
    Verdict.SUCCESS: "🔴 SUCCESS (model broken)",
    Verdict.BLOCKED: "🟢 BLOCKED",
    Verdict.PARTIAL: "🟡 PARTIAL",
    Verdict.ERROR: "⚪ ERROR",
}


def render_markdown(report: ScanReport) -> str:
    s = report.summary
    lines: list[str] = []

    lines.append(f"# Robustness report — {report.target_name}")
    lines.append("")
    lines.append(f"- **Target model:** `{report.model}`")
    lines.append(f"- **Date:** {report.started_at}")
    lines.append(f"- **Attacks run:** {s.total}")
    lines.append("")
    lines.append(f"## 🛡️ Robustness score: **{s.robustness_score}/100**")
    lines.append("")
    lines.append(f"- Attack success rate (ASR): **{s.attack_success_rate}%**")
    lines.append(
        f"- 🔴 Successes: {s.success} · 🟢 Blocked: {s.blocked} · "
        f"🟡 Partial: {s.partial} · ⚪ Errors: {s.error}"
    )
    lines.append("")

    lines.append("## Breakdown by category")
    lines.append("")
    lines.append("| Category | Total | 🔴 Success | 🟢 Blocked | 🟡 Partial |")
    lines.append("|---|---|---|---|---|")
    for c in s.by_category:
        lines.append(
            f"| {c.category} | {c.total} | {c.success} | {c.blocked} | {c.partial} |"
        )
    lines.append("")

    # The interesting part: details of the attacks that worked.
    breaks = [r for r in report.results if r.verdict == Verdict.SUCCESS]
    lines.append(f"## 🔴 Attacks that worked ({len(breaks)})")
    lines.append("")
    if not breaks:
        lines.append("_None: the model resisted every attack in this run._")
        lines.append("")
    for r in breaks:
        lines.append(f"### `{r.attack.id}` — {r.attack.category} / {r.attack.technique}")
        lines.append(f"- **Goal:** {r.attack.goal}")
        lines.append(f"- **Verdict:** {_VERDICT_LABEL[r.verdict]} — {r.rationale}")
        lines.append("")
        lines.append("**Prompt sent:**")
        lines.append("```")
        lines.append(r.attack.prompt.strip())
        lines.append("```")
        lines.append("**Model response (truncated):**")
        lines.append("```")
        lines.append(_excerpt(r.response))
        lines.append("```")
        lines.append("")

    lines.append("## Appendix — all results")
    lines.append("")
    lines.append("| Attack | Category | Verdict | Latency (s) |")
    lines.append("|---|---|---|---|")
    for r in report.results:
        lines.append(
            f"| `{r.attack.id}` | {r.attack.category} | "
            f"{_VERDICT_LABEL[r.verdict]} | {r.latency_s} |"
        )
    lines.append("")
    return "\n".join(lines)


def _excerpt(text: str, limit: int = 600) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + " […]"


def render_comparison_markdown(comparison: ComparisonReport) -> str:
    """Render a side-by-side comparison of several models as Markdown."""
    lines: list[str] = []

    lines.append(f"# Model comparison — {comparison.target_name}")
    lines.append("")
    lines.append(f"- **Date:** {comparison.started_at}")
    lines.append(f"- **Models compared:** {len(comparison.reports)}")
    lines.append(f"- **Attacks per model:** {comparison.attacks_total}")
    lines.append("")

    # Leaderboard: most robust model first.
    ranked = sorted(
        comparison.reports,
        key=lambda r: r.summary.robustness_score,
        reverse=True,
    )
    lines.append("## 🏆 Leaderboard (most robust first)")
    lines.append("")
    lines.append("| # | Model | Robustness | ASR | 🔴 | 🟢 | 🟡 | ⚪ |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for rank, r in enumerate(ranked, start=1):
        s = r.summary
        lines.append(
            f"| {rank} | `{r.model}` | **{s.robustness_score}/100** | "
            f"{s.attack_success_rate}% | {s.success} | {s.blocked} | "
            f"{s.partial} | {s.error} |"
        )
    lines.append("")

    # Per-category success counts (higher = the category broke that model more).
    categories = sorted(
        {c.category for r in comparison.reports for c in r.summary.by_category}
    )
    lines.append("## Successful attacks by category")
    lines.append("")
    lines.append("_Cells show successful attacks / total for that category._")
    lines.append("")
    header = "| Category | " + " | ".join(f"`{r.model}`" for r in ranked) + " |"
    lines.append(header)
    lines.append("|---" * (len(ranked) + 1) + "|")
    for cat in categories:
        cells = []
        for r in ranked:
            stat = next(
                (c for c in r.summary.by_category if c.category == cat), None
            )
            cells.append(f"{stat.success}/{stat.total}" if stat else "—")
        lines.append(f"| {cat} | " + " | ".join(cells) + " |")
    lines.append("")

    return "\n".join(lines)
