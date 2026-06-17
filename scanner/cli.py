"""Command-line interface for the scanner."""

from __future__ import annotations

import enum
import sys
from pathlib import Path

import typer
from rich.console import Console

from .attacks.library import load_attacks
from .config import load_target_config
from .judges.base import Judge
from .judges.claude import DEFAULT_MODEL as DEFAULT_JUDGE_MODEL
from .judges.claude import ClaudeJudge
from .judges.heuristic import HeuristicJudge
from .models import Attack, AttackResult, Verdict
from .reporter import render_markdown
from .runner import run_scan
from .targets.ollama import OllamaTarget

app = typer.Typer(help="LLM robustness scanner (prompt injection / jailbreaks).")
console = Console()


class JudgeChoice(str, enum.Enum):
    """Which judge decides whether each attack succeeded."""

    heuristic = "heuristic"  # fast string rules, free, no API key
    claude = "claude"        # nuanced verdicts via the Claude API


def _build_judge(choice: JudgeChoice, judge_model: str) -> Judge:
    """Create the chosen judge, failing with a friendly message if needed."""
    if choice is JudgeChoice.heuristic:
        return HeuristicJudge()
    try:
        return ClaudeJudge(model=judge_model)
    except Exception as exc:  # noqa: BLE001 - usually a missing API key
        console.print(
            "[red]Could not start the Claude judge.[/red] Set your API key with "
            "[bold]ANTHROPIC_API_KEY[/bold] (or use [bold]--judge heuristic[/bold]).\n"
            f"[dim]{exc}[/dim]"
        )
        raise typer.Exit(code=1)


@app.callback()
def main() -> None:
    """LLM robustness scanner (prompt injection / jailbreaks).

    This callback does nothing visible, but it serves two purposes: (1) it forces
    typer to treat the app as a group of subcommands (e.g. `run`), and (2) it
    forces UTF-8 output so emojis and `→` don't crash on Windows.
    """
    # On Windows the console defaults to cp1252 and fails to print characters
    # like → or emojis. Force UTF-8 on stdout/stderr.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except Exception:  # noqa: BLE001 - if it can't, just carry on
                pass


_VERDICT_STYLE = {
    Verdict.SUCCESS: "bold red",
    Verdict.BLOCKED: "bold green",
    Verdict.PARTIAL: "yellow",
    Verdict.ERROR: "dim",
}


@app.command()
def run(
    target: Path = typer.Option(..., "--target", "-t", help="Target YAML file."),
    attacks: Path = typer.Option(..., "--attacks", "-a", help="Attacks YAML file."),
    out: Path = typer.Option(Path("reports"), "--out", "-o", help="Output folder."),
    host: str = typer.Option(
        "http://localhost:11434", help="Ollama API host."
    ),
    judge: JudgeChoice = typer.Option(
        JudgeChoice.heuristic,
        "--judge",
        "-j",
        help="Who decides if an attack worked: 'heuristic' (free) or 'claude'.",
    ),
    judge_model: str = typer.Option(
        DEFAULT_JUDGE_MODEL,
        "--judge-model",
        help="Claude model for the 'claude' judge.",
    ),
) -> None:
    """Run the attack suite against the target model and generate the report."""
    target_cfg = load_target_config(target)
    attack_list = load_attacks(attacks)

    console.print(
        f"[bold]Target:[/bold] {target_cfg.name}  "
        f"([cyan]{target_cfg.model}[/cyan])"
    )
    console.print(
        f"[bold]Attacks:[/bold] {len(attack_list)}   "
        f"[bold]Judge:[/bold] {judge.value}\n"
    )

    model_target = OllamaTarget(
        model=target_cfg.model,
        system_prompt=target_cfg.system_prompt,
        host=host,
    )
    judge_impl = _build_judge(judge, judge_model)

    def on_progress(i: int, n: int, atk: Attack) -> None:
        console.print(
            f"[dim]({i}/{n})[/dim] Testing [bold]{atk.id}[/bold] "
            f"([italic]{atk.technique}[/italic])…"
        )

    def on_result(r: AttackResult) -> None:
        style = _VERDICT_STYLE[r.verdict]
        console.print(
            f"    → [{style}]{r.verdict.value.upper()}[/{style}]  "
            f"({r.latency_s}s)  {r.rationale}"
        )

    report = run_scan(
        model_target, target_cfg, attack_list, judge_impl, on_progress, on_result
    )

    s = report.summary
    console.print(
        f"\n[bold]🛡️  Robustness: {s.robustness_score}/100[/bold]  "
        f"(ASR {s.attack_success_rate}%)   "
        f"[red]{s.success} success[/red] / [green]{s.blocked} blocked[/green] / "
        f"[yellow]{s.partial} partial[/yellow] / [dim]{s.error} err[/dim]"
    )

    out.mkdir(parents=True, exist_ok=True)
    stamp = report.started_at.replace(":", "-")
    md_path = out / f"report_{stamp}.md"
    json_path = out / f"report_{stamp}.json"
    md_path.write_text(render_markdown(report), encoding="utf-8")
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    console.print(f"\n[green]✔[/green] Markdown report: [bold]{md_path}[/bold]")
    console.print(f"[green]✔[/green] JSON data:       [bold]{json_path}[/bold]")


if __name__ == "__main__":
    app()
