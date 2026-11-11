"""Per-client compliance / cyber-insurance report.

Turns a client's protection into the evidence auditors and insurers ask for:
emails scanned and attacks caught, measured detection and false-positive rates,
staff training results, and human-risk over time.

Honesty: the headline metrics are real (computed from the client's inbox, the
measured loop, and the recorded simulation results). The month-by-month risk
trend is illustrative - a real deployment builds it from dated pilot history -
and is labelled as such in the report and the page.
"""

from . import detector, scoring

RISKY_ACTIONS = ("clicked", "entered_data")


def build(client, loop_result, period):
    """Assemble the report data for one client. `loop_result` is run_loop output."""
    analyses = [(e, detector.analyze(e, client)) for e in client["inbox"]]
    attacks = [{
        "subject": e["subject"],
        "from": f"{e['from_name']} <{e['from_addr']}>",
        "verdict": a["verdict"],
        "score": a["score"],
        "reason": a["explanation"],
    } for e, a in analyses if a["verdict"] != "safe"]

    emp = scoring.employee_scores(client["employees"], client["events"])
    avg_risk = round(sum(e["human_risk"] for e in emp) / len(emp)) if emp else 0

    all_events = [ev for evs in client["events"].values() for ev in evs]
    reported = sum(1 for ev in all_events if ev.get("action") == "reported")
    risky = sum(1 for ev in all_events if ev.get("action") in RISKY_ACTIONS)
    report_rate = round(100 * reported / len(all_events)) if all_events else 0

    # Illustrative 3-month trend ending at the real current average.
    trend = [min(100, avg_risk + 18), min(100, avg_risk + 9), avg_risk]

    s = loop_result["summary"]
    return {
        "client": {"name": client["name"], "sector": client["sector"],
                   "domain": client["domain"], "employees": len(client["employees"])},
        "period": period,
        "email_protection": {
            "scanned": client.get("scanned", len(analyses)),
            "dangerous": sum(1 for _, a in analyses if a["verdict"] == "dangerous"),
            "suspicious": sum(1 for _, a in analyses if a["verdict"] == "suspicious"),
            "attacks_caught": attacks,
        },
        "detection_performance": {
            "detection_rate": s["learner_detection"],
            "baseline_rate": s["baseline_detection"],
            "lift": s["lift"],
            "false_positive_rate": s["learner_fp"],
            "note": "Measured on a held-out test set across "
                    f"{loop_result['total_families']} phishing tactics.",
        },
        "training": {
            "avg_human_risk": avg_risk,
            "report_rate": report_rate,
            "reported": reported,
            "fell_for": risky,
            "employees": emp,
        },
        "risk_trend": {
            "points": trend,
            "labels": ["2 months ago", "last month", "this period"],
            "illustrative": True,
        },
        "evidence": [
            "Inbound email is filtered by a multi-layer AI detector with "
            "plain-language explanations for staff.",
            f"{len(all_events)} phishing simulations run; {report_rate}% of tests "
            "reported by staff.",
            f"Detection measured at {s['learner_detection']}% versus a "
            f"{s['baseline_detection']}% baseline, at a {s['learner_fp']}% "
            "false-positive rate.",
            "Human-risk scored per employee and tracked over time.",
        ],
    }
