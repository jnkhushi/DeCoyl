"""Training simulator: generate SAFE, LABELLED phishing-awareness tests.

Safety design for the prototype:
  * Targets are synthetic personas only (passed in from the demo org).
  * Every generated email is tagged simulation=True and carries a training
    banner, so it can never be mistaken for a real attack.
  * Links are inert placeholders on example.com, never real payloads.
  * Nothing is sent anywhere; the email is returned for display in the dashboard.

This mirrors how awareness-training platforms teach staff to spot attacks. It
deliberately does not produce deployable attacks against real people.
"""

import random

TRAINING_BANNER = ("[DECOYL TRAINING SIMULATION - not a real email. "
                   "If you spot the red flags, report it.]")

# Templates by difficulty. Placeholders are filled from a synthetic persona.
# Links always resolve to the inert example.com training range.
TEMPLATES = {
    "easy": {
        "from_name": "IT Helpdesk",
        "from_addr": "support@acme-corp-it.example.com",
        "subject": "Your mailbox is almost full",
        "body": "Hi {name}, your mailbox is 98% full. Click here to get more space: "
                "https://training.example.com/mailbox . Thanks, IT Helpdesk",
        "red_flags": ["Generic greeting", "Unfamiliar sender domain",
                      "Link to an outside site"],
    },
    "medium": {
        "from_name": "Payroll",
        "from_addr": "payroll@acme-payrol.example.com",
        "subject": "Update your bank details for this month's pay",
        "body": "Hi {name}, we are updating payroll records. Please confirm your bank "
                "details today to avoid a delay in your salary: "
                "https://training.example.com/payroll . Payroll Team",
        "red_flags": ["Lookalike domain (acme-payrol)", "Urgency about pay",
                      "Asks for bank details"],
    },
    "hard": {
        "from_name": "{manager}",
        "from_addr": "{manager_handle}@gmail.example.com",
        "subject": "Quick favour re: {project}",
        "body": "Hi {name}, I'm between meetings on {project} and can't get to my desk. "
                "Can you buy two $100 gift cards for a client and send me the codes? "
                "I'll expense it later. Keep it quick - thanks, {manager}",
        "red_flags": ["Boss impersonation from a personal address",
                      "References a real project to build trust",
                      "Gift-card request", "Urgency + secrecy"],
    },
}


def generate(persona, difficulty="medium", org=None):
    """Return one synthetic training email for a persona.

    persona: {"name", "email", "manager", ...} from the demo org.
    """
    if difficulty not in TEMPLATES:
        difficulty = "medium"
    t = TEMPLATES[difficulty]
    manager = persona.get("manager") or "A Manager"
    manager_handle = manager.lower().replace(" ", ".")
    project = (org or {}).get("projects", ["an active project"])
    project = random.choice(project) if project else "an active project"

    fill = {
        "name": persona["name"].split()[0],
        "manager": manager,
        "manager_handle": manager_handle,
        "project": project,
    }
    return {
        "id": f"sim-{random.randint(1000, 9999)}",
        "simulation": True,
        "difficulty": difficulty,
        "banner": TRAINING_BANNER,
        "from_name": t["from_name"].format(**fill),
        "from_addr": t["from_addr"].format(**fill),
        "to": persona["email"],
        "subject": t["subject"].format(**fill),
        "body": t["body"].format(**fill),
        "red_flags": t["red_flags"],
        # Simulations deliberately fail auth, like the real attacks they teach.
        "auth": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
    }
