"""Human-risk scoring: how likely an employee is to fall for a real attack.

Built from their reactions to past simulations. Higher score = higher risk.
Starts from a neutral baseline and moves with each recorded event.
"""

BASELINE = 50
# How much each reaction moves the risk score. Falling for a test raises risk;
# reporting it lowers risk.
WEIGHTS = {
    "entered_data": 30,   # typed a password / bank details into the fake page
    "clicked": 15,        # clicked the link
    "opened": 5,          # opened the email but took no further action
    "ignored": -2,        # left it alone
    "reported": -20,      # reported it as phishing (the ideal response)
}


def human_risk(events):
    """Return a 0-100 risk score for one employee from their simulation history."""
    score = BASELINE + sum(WEIGHTS.get(e.get("action"), 0) for e in events)
    return max(0, min(100, score))


def risk_band(score):
    if score >= 66:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def employee_scores(employees, events_by_email):
    """Attach a human-risk score and band to each employee."""
    out = []
    for emp in employees:
        events = events_by_email.get(emp["email"], [])
        score = human_risk(events)
        out.append({
            "name": emp["name"],
            "email": emp["email"],
            "role": emp["role"],
            "human_risk": score,
            "band": risk_band(score),
            "tests": len(events),
        })
    return out
