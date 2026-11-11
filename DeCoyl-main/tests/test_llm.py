"""Tests for the Claude ensemble merge (no API key needed).

apply_claude is a pure function, so the ensemble logic is tested with simulated
Claude assessments. The live call in assess() needs a key and is not unit-tested.
"""

from app import data, detector, llm


def _result(email_id="e5"):
    acme = data.get_client("acme")
    email = next(e for e in acme["inbox"] if e["id"] == email_id)
    r = detector.analyze(email, acme)
    r["signals"] = list(r["signals"])   # own copy for the test
    return r


def test_no_assessment_keeps_heuristic_result():
    before = _result("e2")
    verdict, score = before["verdict"], before["score"]
    after = llm.apply_claude(before, None)
    assert after["explained_by"] == "heuristic"
    assert after["verdict"] == verdict and after["score"] == score
    assert "claude" not in after


def test_confident_phishing_lifts_a_borderline_verdict():
    r = _result("e5")                       # the spear-phish, heuristic ~suspicious
    assert r["verdict"] == "suspicious"
    out = llm.apply_claude(r, {"is_phishing": True, "confidence": 95,
                               "reason": "Asks to reset a login from an outside account.",
                               "model": "claude-opus-5-5"})
    assert out["verdict"] == "dangerous"    # ensemble raised it
    assert out["explained_by"] == "claude"
    assert any(s["type"] == "claude" for s in out["signals"])


def test_claude_legitimate_does_not_lower_a_heuristic_danger():
    r = _result("e2")                       # BEC wire fraud, heuristic dangerous/100
    out = llm.apply_claude(r, {"is_phishing": False, "confidence": 80,
                               "reason": "Looks like a normal internal request.",
                               "model": "claude-opus-5-5"})
    # Safer verdict wins; the disagreement is still recorded.
    assert out["verdict"] == "dangerous"
    assert out["claude"]["is_phishing"] is False


def test_assess_is_dormant_without_a_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert llm.available() is False
    assert llm.assess({"subject": "x", "body": "y"}) is None
