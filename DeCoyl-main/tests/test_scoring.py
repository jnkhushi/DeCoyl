"""Tests for human-risk scoring and the simulator's safety guarantees."""

from app import data, scoring, simulator


def test_reporting_lowers_risk_below_baseline():
    score = scoring.human_risk([{"action": "reported"}, {"action": "reported"}])
    assert score < scoring.BASELINE
    assert scoring.risk_band(score) == "low"


def test_falling_for_tests_raises_risk():
    score = scoring.human_risk([{"action": "clicked"}, {"action": "entered_data"}])
    assert score > scoring.BASELINE
    assert scoring.risk_band(score) == "high"


def test_score_is_clamped_0_100():
    assert scoring.human_risk([{"action": "entered_data"}] * 20) == 100
    assert scoring.human_risk([{"action": "reported"}] * 20) == 0


def test_simulation_is_labelled_and_synthetic():
    import re
    persona = data.ORG["employees"][1]
    for difficulty in ("easy", "medium", "hard"):
        sim = simulator.generate(persona, difficulty, data.ORG)
        assert sim["simulation"] is True
        assert "TRAINING SIMULATION" in sim["banner"]
        # Sender stays in the inert example range, never a real domain.
        assert "example." in sim["from_addr"]
        # Any link in the body must point at the inert example.com range.
        for url in re.findall(r"https?://[^\s]+", sim["body"]):
            assert "example.com" in url
        assert sim["red_flags"]
