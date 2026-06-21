"""Tests for the adaptive (escalating) runner. Pure orchestration logic, fully
offline: fake target, fake judge, and a fake attacker stand in for Ollama and the
Claude API.

The behaviour under test is the escalation loop itself — when it keeps rewriting a
blocked attack, when it stops, and that every attempt lands in the report — not the
intelligence of any real model.
"""

from scanner.models import Attack, TargetConfig, Verdict
from scanner.runner import run_adaptive_scan

TARGET = TargetConfig(name="lab", model="llama-test", system_prompt="be safe")


def _seed(attack_id="seed") -> Attack:
    return Attack(id=attack_id, category="jailbreak", technique="t", goal="g", prompt="p")


class _FakeTarget:
    """Echoes the prompt back; verdicts are decided by the judge, not here."""

    name = "lab"
    model = "llama-test"

    def generate(self, prompt: str) -> str:
        return f"resp:{prompt}"


class _ScriptedJudge:
    """Returns a verdict per attack id; anything unlisted defaults to BLOCKED."""

    def __init__(self, verdicts: dict[str, Verdict]):
        self.verdicts = verdicts

    def judge(self, attack, response, target):
        return self.verdicts.get(attack.id, Verdict.BLOCKED), "scripted"


class _FakeGenerator:
    """Stands in for ClaudeAttackGenerator.adapt: ids the variant by round and
    counts calls. If `fail` is True, raises (simulating an API error)."""

    def __init__(self, fail: bool = False):
        self.calls: list[tuple[str, int]] = []
        self.fail = fail

    def adapt(self, attack, response, target, round_no):
        self.calls.append((attack.id, round_no))
        if self.fail:
            raise RuntimeError("attacker API down")
        return Attack(
            id=f"{attack.id}~r{round_no}",
            category=attack.category,
            technique=f"adapted:{round_no}",
            goal=attack.goal,
            prompt=f"adapted-{round_no}",
            detection=attack.detection,
            success_markers=attack.success_markers,
        )


def _run(judge, generator, max_rounds=2, seeds=None):
    adaptations: list = []
    report = run_adaptive_scan(
        _FakeTarget(),
        TARGET,
        seeds or [_seed()],
        judge,
        generator,
        max_rounds=max_rounds,
        on_adapt=lambda blocked, rnd, new, err: adaptations.append((blocked.id, rnd, new, err)),
    )
    return report, adaptations


def test_stops_escalating_once_an_attack_breaks_through():
    judge = _ScriptedJudge({"seed": Verdict.BLOCKED, "seed~r1": Verdict.SUCCESS})
    gen = _FakeGenerator()
    report, _ = _run(judge, gen, max_rounds=2)

    ids = [r.attack.id for r in report.results]
    assert ids == ["seed", "seed~r1"]            # stopped after the success
    assert report.results[-1].verdict == Verdict.SUCCESS
    assert gen.calls == [("seed", 1)]            # adapted exactly once


def test_escalates_until_max_rounds_then_stops():
    judge = _ScriptedJudge({})  # everything BLOCKED
    gen = _FakeGenerator()
    report, _ = _run(judge, gen, max_rounds=2)

    # ids nest, so the lineage of each escalation is visible in the report
    ids = [r.attack.id for r in report.results]
    assert ids == ["seed", "seed~r1", "seed~r1~r2"]  # seed + 2 adaptation rounds
    assert gen.calls == [("seed", 1), ("seed~r1", 2)]
    assert all(r.verdict == Verdict.BLOCKED for r in report.results)


def test_no_adaptation_when_seed_is_not_blocked():
    judge = _ScriptedJudge({"seed": Verdict.SUCCESS})
    gen = _FakeGenerator()
    report, adaptations = _run(judge, gen, max_rounds=2)

    assert [r.attack.id for r in report.results] == ["seed"]
    assert gen.calls == []          # never asked Claude to adapt
    assert adaptations == []


def test_adaptation_failure_stops_the_chain_and_is_reported():
    judge = _ScriptedJudge({})      # would keep escalating
    gen = _FakeGenerator(fail=True)
    report, adaptations = _run(judge, gen, max_rounds=2)

    assert [r.attack.id for r in report.results] == ["seed"]  # only the seed ran
    assert gen.calls == [("seed", 1)]                         # tried once, raised
    # on_adapt fired with an error and no new attack
    assert len(adaptations) == 1
    blocked_id, rnd, new, err = adaptations[0]
    assert blocked_id == "seed" and new is None and "down" in err


def test_each_seed_escalates_independently():
    judge = _ScriptedJudge({"a": Verdict.SUCCESS})  # 'a' breaks at once, 'b' resists
    gen = _FakeGenerator()
    report, _ = _run(judge, gen, max_rounds=1, seeds=[_seed("a"), _seed("b")])

    ids = [r.attack.id for r in report.results]
    assert ids == ["a", "b", "b~r1"]
    assert report.target_name == "lab"
    assert report.model == "llama-test"
    assert report.summary.total == 3
