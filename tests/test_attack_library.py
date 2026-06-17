"""Tests for the attack suites (YAML). Pure file loading: no network.

These guard the data, not the model: a typo in a YAML file, a duplicate id, or a
marker-based attack with no success markers (which could never be detected as a
success) would all be caught here.
"""

from pathlib import Path

import pytest

from scanner.attacks.library import load_attacks
from scanner.models import DetectionType

ATTACKS_DIR = Path(__file__).resolve().parent.parent / "data" / "attacks"
SUITES = ["starter.yaml", "full.yaml"]


@pytest.mark.parametrize("suite", SUITES)
def test_suite_loads(suite):
    attacks = load_attacks(ATTACKS_DIR / suite)
    assert attacks, f"{suite} should not be empty"


@pytest.mark.parametrize("suite", SUITES)
def test_ids_are_unique(suite):
    ids = [a.id for a in load_attacks(ATTACKS_DIR / suite)]
    assert len(ids) == len(set(ids)), f"duplicate attack ids in {suite}"


@pytest.mark.parametrize("suite", SUITES)
def test_marker_attacks_have_markers(suite):
    for atk in load_attacks(ATTACKS_DIR / suite):
        if atk.detection == DetectionType.MARKERS:
            assert atk.success_markers, (
                f"{atk.id} in {suite} uses marker detection but has no "
                f"success_markers, so it could never be scored as a success"
            )


def test_full_suite_is_broader_than_starter():
    starter = load_attacks(ATTACKS_DIR / "starter.yaml")
    full = load_attacks(ATTACKS_DIR / "full.yaml")
    assert len(full) > len(starter)
    # the full suite should cover more categories than the starter
    assert {a.category for a in full} >= {a.category for a in starter}
