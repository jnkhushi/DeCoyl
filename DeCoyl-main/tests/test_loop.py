"""Tests for the self-improving loop.

Assertions are on the loop's mechanics (it learns, beats the frozen baseline,
keeps false positives low), not on exact numbers. The seed is fixed so the run
is deterministic.
"""

from app import loop


def test_learner_improves_and_beats_frozen_baseline():
    r = loop.run_loop(rounds=5, seed=7)
    curve = r["curve"]
    first, last = curve[0], curve[-1]

    # The detector learns: detection at the end is higher than at the seed start.
    assert last["learner_detection"] > first["learner_detection"]
    # It beats the baseline that never retrains.
    assert last["learner_detection"] > last["baseline_detection"]
    assert r["summary"]["lift"] > 0


def test_baseline_is_frozen():
    r = loop.run_loop(rounds=5, seed=7)
    baseline = [c["baseline_detection"] for c in r["curve"]]
    assert len(set(baseline)) == 1   # never changes — it does not retrain


def test_false_positive_rate_stays_low():
    r = loop.run_loop(rounds=5, seed=7)
    assert all(c["learner_fp"] <= 15 for c in r["curve"])


def test_new_tactic_evades_before_feedback():
    r = loop.run_loop(rounds=5, seed=7)
    # The first round introduces an unseen tactic, so the learner misses some of
    # it before those misses feed back into training.
    assert r["curve"][1]["misses"] > 0


def test_rounds_are_capped_to_available_families():
    r = loop.run_loop(rounds=999, seed=7)
    assert r["rounds"] == r["total_families"] - r["seed_families"]
