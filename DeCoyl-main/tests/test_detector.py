"""Tests for the four-layer defender."""

from app import data, detector

ORG = data.ORG


def _email(**kw):
    base = {"from_name": "", "from_addr": "x@external.example", "subject": "",
            "body": "", "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"}}
    base.update(kw)
    return base


def test_levenshtein():
    assert detector._levenshtein("acme-corp.com", "acme-corp.com") == 0
    assert detector._levenshtein("acme-corp.com", "acrne-corp.com") <= 2
    assert detector._levenshtein("", "abc") == 3


def test_lookalike_catches_homoglyph_and_typo():
    trusted = {"acme-corp.com", "microsoft.com"}
    assert detector._lookalike_of("acrne-corp.com", trusted) == "acme-corp.com"
    assert detector._lookalike_of("rnicrosoft.com", trusted) == "microsoft.com"
    # A genuinely different domain must not be flagged.
    assert detector._lookalike_of("northwind-supplies.com", trusted) is None
    # A trusted domain is never its own lookalike.
    assert detector._lookalike_of("acme-corp.com", trusted) is None


def test_legit_internal_email_is_safe():
    email = _email(from_name="John Carter", from_addr="john.carter@acme-corp.com",
                   subject="Lunch Friday?", body="Are you free for lunch Friday?")
    result = detector.analyze(email, ORG)
    assert result["verdict"] == "safe"
    assert result["score"] == 0


def test_bec_wire_fraud_is_dangerous():
    email = _email(
        from_name="John Carter", from_addr="john.carter@acrne-corp.com",
        subject="Urgent wire transfer needed",
        body="Please wire $48,000 immediately and keep this confidential.",
        auth={"spf": "fail", "dkim": "none", "dmarc": "fail"},
    )
    result = detector.analyze(email, ORG)
    assert result["verdict"] == "dangerous"
    types = {s["type"] for s in result["signals"]}
    assert "sender_lookalike" in types     # layer 2
    assert "payment" in types              # layer 1
    assert "display_name_spoof" in types   # layer 2


def test_credential_phish_flags_shortener_and_auth():
    email = _email(
        from_name="Microsoft 365", from_addr="no-reply@rnicrosoft-support.com",
        subject="Verify your password now",
        body="Verify your account: https://bit.ly/ms-verify to confirm your credentials.",
        auth={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
    )
    result = detector.analyze(email, ORG)
    types = {s["type"] for s in result["signals"]}
    assert "url_shortener" in types
    assert "credential" in types
    assert result["verdict"] == "dangerous"


def test_spearphish_internal_detail_from_external_sender():
    email = _email(
        from_name="Priya Shah", from_addr="priya.shah.work@gmail.com",
        subject="Project Atlas access",
        body="Can you reset my Project Atlas login? John asked me to sort this today.",
    )
    sigs = detector.layer3_spearphish(email, ORG)
    assert sigs and sigs[0]["type"] == "spearphish"


def test_spearphish_not_triggered_from_trusted_internal_sender():
    email = _email(
        from_name="Priya Shah", from_addr="priya.shah@acme-corp.com",
        subject="Project Atlas", body="Project Atlas standup moved to 2pm.",
    )
    assert detector.layer3_spearphish(email, ORG) == []
