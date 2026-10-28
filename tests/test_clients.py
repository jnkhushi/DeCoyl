"""Tests for the multi-tenant client registry and per-client isolation."""

from app import data, detector, scoring


def test_three_distinct_clients():
    clients = data.list_clients()
    ids = {c["id"] for c in clients}
    assert ids == {"acme", "brightsmile", "ledgerline"}
    # Each client has its own domain, people and inbox.
    for c in clients:
        assert c["domain"] and c["employees"] and c["inbox"]
        assert c["loop_seed"]


def test_get_unknown_client_is_none():
    assert data.get_client("nope") is None


def test_each_client_inbox_has_a_dangerous_and_a_safe_email():
    for c in data.list_clients():
        verdicts = [detector.analyze(e, c)["verdict"] for e in c["inbox"]]
        assert "dangerous" in verdicts
        assert "safe" in verdicts


def test_detection_is_scoped_to_the_right_client():
    # BrightSmile's lookalike (brightsmile-dentol.com) is dangerous for BrightSmile...
    bs = data.get_client("brightsmile")
    d2 = next(e for e in bs["inbox"] if e["id"] == "d2")
    assert detector.analyze(d2, bs)["verdict"] == "dangerous"
    # ...but that same domain is just an unknown outside sender to Acme, so Acme's
    # lookalike signal does not fire for it.
    acme = data.get_client("acme")
    sigs = detector.layer2_forensics(d2, acme)
    assert not any(s["type"] == "sender_lookalike" for s in sigs)


def test_employee_scores_use_each_clients_own_events():
    ll = data.get_client("ledgerline")
    scores = {e["name"]: e for e in scoring.employee_scores(ll["employees"], ll["events"])}
    assert scores["Daniel Osei"]["band"] == "high"   # clicked + entered data
    assert scores["Grace Kim"]["band"] == "low"       # reported twice
