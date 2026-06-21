"""Command-line interface for the scanner."""

from __future__ import annotations

import enum
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from .attacks.generator import DEFAULT_MODEL as DEFAULT_ATTACKER_MODEL
from .attacks.generator import ClaudeAttackGenerator
from .attacks.library import load_attacks
from .config import load_target_config
from .judges.base import Judge
from .judges.claude import DEFAULT_MODEL as DEFAULT_JUDGE_MODEL
from .judges.claude import ClaudeJudge
from .judges.heuristic import HeuristicJudge
from .models import Attack, AttackResult, Verdict
from .html_reporter import render_comparison_html, render_html
from .reporter import render_comparison_markdown, render_markdown
from .runner import run_adaptive_scan, run_comparison, run_scan
from .targets.ollama import OllamaTarget

app = typer.Typer(help="LLM robustness scanner (prompt injection / jailbreaks).")
console = Console()


class JudgeChoice(str, enum.Enum):
    """Which judge decides whether each attack succeeded."""

    heuristic = "heuristic"  # fast string rules, free, no API key
    claude = "claude"        # nuanced verdicts via the Claude API


class OutputFormat(str, enum.Enum):
    """Which human-readable report(s) to write (JSON data is always written)."""

    md = "md"      # Markdown only
    html = "html"  # self-contained HTML only
    both = "both"  # Markdown + HTML


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


def _build_generator(attacker_model: str) -> ClaudeAttackGenerator:
    """Create the Claude attacker (for --generate / --adapt), failing friendly."""
    try:
        return ClaudeAttackGenerator(model=attacker_model)
    except Exception as exc:  # noqa: BLE001 - usually a missing API key
        console.print(
            "[red]Could not start the Claude attacker.[/red] --generate and "
            "--adapt need an API key in [bold]ANTHROPIC_API_KEY[/bold].\n"
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
    attacks: Optional[Path] = typer.Option(
        None,
        "--attacks",
        "-a",
        help="Attacks YAML file (seed suite). Optional if --generate is used.",
    ),
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
    generate: int = typer.Option(
        0,
        "--generate",
        "-g",
        help="Ask Claude to generate N extra attacks tailored to the target "
        "(needs ANTHROPIC_API_KEY; paid).",
    ),
    adapt: bool = typer.Option(
        False,
        "--adapt/--no-adapt",
        help="When an attack is blocked, have Claude rewrite and retry it "
        "(escalation; needs ANTHROPIC_API_KEY; paid).",
    ),
    max_rounds: int = typer.Option(
        2,
        "--max-rounds",
        help="Max Claude adaptation rounds per attack when --adapt is on.",
    ),
    attacker_model: str = typer.Option(
        DEFAULT_ATTACKER_MODEL,
        "--attacker-model",
        help="Claude model used to generate/adapt attacks.",
    ),
    fmt: OutputFormat = typer.Option(
        OutputFormat.both,
        "--format",
        "-f",
        help="Report format: 'md', 'html', or 'both' (JSON is always written).",
    ),
) -> None:
    """Run the attack suite against the target model and generate the report."""
    target_cfg = load_target_config(target)
    attack_list = load_attacks(attacks) if attacks is not None else []

    # --generate and --adapt both turn Claude into the attacker; build it once.
    generator = _build_generator(attacker_model) if (generate > 0 or adapt) else None

    if generate > 0:
        console.print(
            f"[bold]Generating {generate} attacks with Claude[/bold] "
            f"([cyan]{attacker_model}[/cyan])…"
        )
        try:
            attack_list += generator.generate(target_cfg, n=generate)
        except Exception as exc:  # noqa: BLE001 - surface API errors cleanly
            console.print(f"[red]Attack generation failed:[/red] [dim]{exc}[/dim]")
            raise typer.Exit(code=1)

    if not attack_list:
        console.print(
            "[red]No attacks to run.[/red] Pass [bold]--attacks[/bold] and/or "
            "[bold]--generate N[/bold]."
        )
        raise typer.Exit(code=2)

    console.print(
        f"[bold]Target:[/bold] {target_cfg.name}  "
        f"([cyan]{target_cfg.model}[/cyan])"
    )
    console.print(
        f"[bold]Attacks:[/bold] {len(attack_list)}   "
        f"[bold]Judge:[/bold] {judge.value}"
        + (f"   [bold]Adapt:[/bold] on (≤{max_rounds} rounds)" if adapt else "")
        + "\n"
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

    def on_adapt(
        blocked: Attack, round_no: int, new_attack: Optional[Attack], error: Optional[str]
    ) -> None:
        if error is not None:
            console.print(f"    [dim]↳ could not adapt (round {round_no}): {error}[/dim]")
        else:
            console.print(
                f"    [magenta]↳ adapting[/magenta] [bold]{blocked.id}[/bold] "
                f"(round {round_no}) → [bold]{new_attack.id}[/bold]…"
            )

    if adapt:
        report = run_adaptive_scan(
            model_target, target_cfg, attack_list, judge_impl, generator,
            max_rounds=max_rounds,
            on_progress=on_progress, on_result=on_result, on_adapt=on_adapt,
        )
    else:
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

    _write_reports(
        out,
        f"report_{report.started_at.replace(':', '-')}",
        json_text=report.model_dump_json(indent=2),
        md_text=render_markdown(report) if fmt is not OutputFormat.html else None,
        html_text=render_html(report) if fmt is not OutputFormat.md else None,
    )


@app.command()
def compare(
    target: Path = typer.Option(..., "--target", "-t", help="Target YAML file."),
    attacks: Path = typer.Option(..., "--attacks", "-a", help="Attacks YAML file."),
    models: str = typer.Option(
        ...,
        "--models",
        "-m",
        help="Comma-separated models to compare, e.g. 'llama3.1:8b,phi3:mini'.",
    ),
    out: Path = typer.Option(Path("reports"), "--out", "-o", help="Output folder."),
    host: str = typer.Option("http://localhost:11434", help="Ollama API host."),
    judge: JudgeChoice = typer.Option(
        JudgeChoice.heuristic, "--judge", "-j",
        help="Who decides if an attack worked: 'heuristic' (free) or 'claude'.",
    ),
    judge_model: str = typer.Option(
        DEFAULT_JUDGE_MODEL, "--judge-model",
        help="Claude model for the 'claude' judge.",
    ),
    fmt: OutputFormat = typer.Option(
        OutputFormat.both, "--format", "-f",
        help="Report format: 'md', 'html', or 'both' (JSON is always written).",
    ),
) -> None:
    """Run the same attack suite against several models and rank them."""
    target_cfg = load_target_config(target)
    attack_list = load_attacks(attacks)
    model_list = [m.strip() for m in models.split(",") if m.strip()]
    if not model_list:
        console.print("[red]No models given.[/red] Use --models 'a,b,c'.")
        raise typer.Exit(code=1)

    console.print(
        f"[bold]Target:[/bold] {target_cfg.name}   "
        f"[bold]Models:[/bold] {', '.join(model_list)}\n"
        f"[bold]Attacks:[/bold] {len(attack_list)}   "
        f"[bold]Judge:[/bold] {judge.value}\n"
    )

    judge_impl = _build_judge(judge, judge_model)

    def target_factory(model: str):
        return OllamaTarget(
            model=model, system_prompt=target_cfg.system_prompt, host=host
        )

    def on_model(i: int, n: int, model: str) -> None:
        console.print(f"\n[bold cyan]── Model {i}/{n}: {model} ──[/bold cyan]")

    def on_result(r: AttackResult) -> None:
        style = _VERDICT_STYLE[r.verdict]
        console.print(
            f"    [bold]{r.attack.id}[/bold] → "
            f"[{style}]{r.verdict.value.upper()}[/{style}] ({r.latency_s}s)"
        )

    comparison = run_comparison(
        model_list, target_cfg, attack_list, judge_impl, target_factory,
        on_model=on_model, on_result=on_result,
    )

    console.print("\n[bold]🏆 Leaderboard (most robust first):[/bold]")
    for rank, r in enumerate(
        sorted(comparison.reports, key=lambda r: r.summary.robustness_score,
               reverse=True),
        start=1,
    ):
        console.print(
            f"  {rank}. [cyan]{r.model}[/cyan]  "
            f"[bold]{r.summary.robustness_score}/100[/bold]  "
            f"(ASR {r.summary.attack_success_rate}%)"
        )

    _write_reports(
        out,
        f"comparison_{comparison.started_at.replace(':', '-')}",
        json_text=comparison.model_dump_json(indent=2),
        md_text=(
            render_comparison_markdown(comparison)
            if fmt is not OutputFormat.html else None
        ),
        html_text=(
            render_comparison_html(comparison)
            if fmt is not OutputFormat.md else None
        ),
    )


def _write_reports(
    out: Path,
    stem: str,
    json_text: str,
    md_text: str | None,
    html_text: str | None,
) -> None:
    """Write the JSON data plus whichever human-readable reports were rendered."""
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / f"{stem}.json"
    json_path.write_text(json_text, encoding="utf-8")
    console.print(f"\n[green]✔[/green] JSON data: [bold]{json_path}[/bold]")
    if md_text is not None:
        md_path = out / f"{stem}.md"
        md_path.write_text(md_text, encoding="utf-8")
        console.print(f"[green]✔[/green] Markdown:  [bold]{md_path}[/bold]")
    if html_text is not None:
        html_path = out / f"{stem}.html"
        html_path.write_text(html_text, encoding="utf-8")
        console.print(f"[green]✔[/green] HTML:      [bold]{html_path}[/bold]")


if __name__ == "__main__":
    app()
