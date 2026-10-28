"""Tests for the per-client compliance report builder."""

from app import data, loop, report


def _report(cid):
    client = data.get_client(cid)
    return report.build(client, loop.run_loop(rounds=5, seed=client["loop_seed"]),
                        "October 2026")


def test_report_has_real_protection_and_detection_numbers():
    r = _report("brightsmile")
    ep = r["email_protection"]
    assert ep["scanned"] == data.get_client("brightsmile")["scanned"]   # ~50, not inbox size
    assert ep["dangerous"] >= 1
    # Attacks caught are the non-safe emails, each with a reason.
    assert len(ep["attacks_caught"]) == ep["dangerous"] + ep["suspicious"]
    assert all(a["reason"] for a in ep["attacks_caught"])
    dp = r["detection_performance"]
    assert dp["detection_rate"] > dp["baseline_rate"]     # the measured loop lift
    assert dp["false_positive_rate"] <= 15


def test_training_counts_match_the_clients_events():
    r = _report("ledgerline")
    events = data.get_client("ledgerline")["events"]
    total = sum(len(v) for v in events.values())
    tr = r["training"]
    assert tr["reported"] + tr["fell_for"] <= total
    assert 0 <= tr["avg_human_risk"] <= 100
    assert len(tr["employees"]) == len(data.get_client("ledgerline")["employees"])


def test_risk_trend_is_labelled_illustrative_and_ends_at_current():
    r = _report("acme")
    rt = r["risk_trend"]
    assert rt["illustrative"] is True
    assert rt["points"][-1] == r["training"]["avg_human_risk"]
    assert len(rt["points"]) == len(rt["labels"])
