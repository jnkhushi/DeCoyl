"""Synthetic demo data for the MSP console: several fictional client companies.

Each client (tenant) has its own domain, people, trusted senders, sample inbox,
and simulation history. Everything is fictional; malicious samples use lookalikes
of each client's own made-up domains and public example ranges, so nothing points
at a real target.

A client dict doubles as the "org" the detector takes (it carries domain,
trusted_domains, projects, employees), plus inbox, events, and a loop seed.
"""


def _email(eid, from_name, from_addr, to, subject, body,
           spf="pass", dkim="pass", dmarc="pass"):
    return {
        "id": eid, "from_name": from_name, "from_addr": from_addr, "to": to,
        "subject": subject, "body": body,
        "auth": {"spf": spf, "dkim": dkim, "dmarc": dmarc}, "simulation": False,
    }


# --- Client 1: Acme Corp (logistics) -----------------------------------------
ACME = {
    "id": "acme",
    "name": "Acme Corp",
    "sector": "Logistics",
    "domain": "acme-corp.com",
    "trusted_domains": [
        "acme-corp.com", "northwind-supplies.com", "microsoft.com",
        "payroll-provider.com",
    ],
    "projects": ["Project Atlas", "Q3 Cloud Migration"],
    "loop_seed": 7,
    "scanned": 47,   # total mail scanned this period; the inbox below is the notable sample
    "employees": [
        {"name": "John Carter", "email": "john.carter@acme-corp.com",
         "role": "CEO", "manager": None},
        {"name": "Alice Nguyen", "email": "alice.nguyen@acme-corp.com",
         "role": "Accounts Payable", "manager": "John Carter"},
        {"name": "Bob Lee", "email": "bob.lee@acme-corp.com",
         "role": "IT Administrator", "manager": "John Carter"},
        {"name": "Priya Shah", "email": "priya.shah@acme-corp.com",
         "role": "Project Manager", "manager": "John Carter"},
    ],
    "inbox": [
        _email("e1", "John Carter", "john.carter@acme-corp.com",
               "alice.nguyen@acme-corp.com", "Lunch Friday?",
               "Hi Alice, are you free for a team lunch on Friday? Let me know what "
               "works. Thanks, John"),
        _email("e2", "John Carter", "john.carter@acrne-corp.com",
               "alice.nguyen@acme-corp.com", "Urgent wire transfer needed before 3pm",
               "Alice, I'm in a confidential acquisition meeting and need you to wire "
               "$48,000 to a new vendor immediately. Keep this between us for now. Send "
               "me the bank details confirmation once done. - John",
               spf="fail", dkim="none", dmarc="fail"),
        _email("e3", "Microsoft 365 Security", "no-reply@rnicrosoft-support.com",
               "bob.lee@acme-corp.com", "Action required: verify your password now",
               "Your Microsoft 365 password expires today. Verify your account to avoid "
               "losing access: https://bit.ly/ms-verify-365 . Sign in to confirm your "
               "credentials.", spf="fail", dkim="fail", dmarc="fail"),
        _email("e4", "Northwind Supplies", "billing@northwind-supplies.com",
               "alice.nguyen@acme-corp.com", "Invoice #4821 for October",
               "Hi Alice, please find attached invoice #4821 for October supplies, due "
               "net 30. Reach out with any questions. Regards, Northwind Billing"),
        _email("e5", "Priya Shah", "priya.shah.work@gmail.com",
               "bob.lee@acme-corp.com", "Project Atlas access",
               "Hey Bob, I'm locked out while travelling. Can you reset my Project Atlas "
               "login and send the temporary password here? John asked me to get this "
               "sorted today. Thanks, Priya"),
        _email("e6", "Acme Internal Comms", "comms@acme-corp.com", "all@acme-corp.com",
               "October newsletter",
               "This month's highlights: new office plants, the Q3 Cloud Migration "
               "kickoff, and a reminder to book your leave. Have a great month!"),
    ],
    "events": {
        "alice.nguyen@acme-corp.com": [
            {"action": "reported"}, {"action": "reported"}, {"action": "ignored"}],
        "bob.lee@acme-corp.com": [
            {"action": "clicked"}, {"action": "entered_data"}, {"action": "reported"}],
        "priya.shah@acme-corp.com": [
            {"action": "clicked"}, {"action": "reported"}, {"action": "reported"}],
        "john.carter@acme-corp.com": [
            {"action": "ignored"}, {"action": "reported"}],
    },
}

# --- Client 2: BrightSmile Dental (healthcare clinic) ------------------------
BRIGHTSMILE = {
    "id": "brightsmile",
    "name": "BrightSmile Dental",
    "sector": "Healthcare",
    "domain": "brightsmile-dental.com",
    "trusted_domains": [
        "brightsmile-dental.com", "dentalsupply-co.com", "deltacover-insurance.com",
        "microsoft.com",
    ],
    "projects": ["Patient Portal Rollout", "New Clinic Fitout"],
    "loop_seed": 11,
    "scanned": 53,
    "employees": [
        {"name": "Dr Emma Reyes", "email": "emma.reyes@brightsmile-dental.com",
         "role": "Lead Dentist", "manager": None},
        {"name": "Carla Mendes", "email": "carla.mendes@brightsmile-dental.com",
         "role": "Office Manager", "manager": "Dr Emma Reyes"},
        {"name": "Nina Patel", "email": "nina.patel@brightsmile-dental.com",
         "role": "Receptionist", "manager": "Carla Mendes"},
        {"name": "Omar Haddad", "email": "omar.haddad@brightsmile-dental.com",
         "role": "Hygienist", "manager": "Dr Emma Reyes"},
    ],
    "inbox": [
        _email("d1", "Carla Mendes", "carla.mendes@brightsmile-dental.com",
               "nina.patel@brightsmile-dental.com", "Rota for next week",
               "Hi Nina, I've put next week's front-desk rota in the shared folder. "
               "Shout if the Thursday shift doesn't work. Thanks, Carla"),
        _email("d2", "Dr Emma Reyes", "emma.reyes@brightsmile-dentol.com",
               "carla.mendes@brightsmile-dental.com", "Urgent supplier payment today",
               "Carla, I'm with a patient and can't call. Please wire $9,800 to our new "
               "lab supplier right away - it's time-sensitive and confidential. Send the "
               "bank details confirmation when done. - Emma",
               spf="fail", dkim="none", dmarc="fail"),
        _email("d3", "Microsoft 365 Security", "no-reply@rnicrosoft-support.com",
               "carla.mendes@brightsmile-dental.com", "Mailbox verification required",
               "Your clinic mailbox is almost full and access will be suspended. Verify "
               "your account and confirm your password here: https://bit.ly/bs-verify .",
               spf="fail", dkim="fail", dmarc="fail"),
        _email("d4", "Dental Supply Co", "orders@dentalsupply-co.com",
               "carla.mendes@brightsmile-dental.com", "Order #771 confirmation",
               "Hi Carla, your order #771 of gloves and composites ships Monday, invoice "
               "due net 30 as usual. Thanks for your business."),
        _email("d5", "Omar Haddad", "omar.haddad.dds@gmail.com",
               "nina.patel@brightsmile-dental.com", "Patient Portal Rollout login",
               "Hi Nina, I'm off-site and locked out. Can you reset my Patient Portal "
               "Rollout login and text me the temporary password? Emma needs the records "
               "pulled today. Thanks, Omar"),
        _email("d6", "DeltaCover Insurance", "claims@deltacover-lnsurance.com",
               "carla.mendes@brightsmile-dental.com", "Update your payout bank details",
               "To process this quarter's claim payouts we must verify your practice "
               "bank details. Confirm the account immediately here: "
               "https://training.example.com/claims or payments will be held.",
               spf="fail", dkim="fail", dmarc="fail"),
    ],
    "events": {
        "emma.reyes@brightsmile-dental.com": [
            {"action": "reported"}, {"action": "ignored"}],
        "carla.mendes@brightsmile-dental.com": [
            {"action": "reported"}, {"action": "reported"}, {"action": "ignored"}],
        "nina.patel@brightsmile-dental.com": [
            {"action": "clicked"}, {"action": "entered_data"}, {"action": "clicked"}],
        "omar.haddad@brightsmile-dental.com": [
            {"action": "clicked"}, {"action": "reported"}, {"action": "ignored"}],
    },
}

# --- Client 3: LedgerLine Accounting (accounting firm) -----------------------
LEDGERLINE = {
    "id": "ledgerline",
    "name": "LedgerLine Accounting",
    "sector": "Accounting",
    "domain": "ledgerline-cpa.com",
    "trusted_domains": [
        "ledgerline-cpa.com", "firstnational-bank.com", "taxsoftpro.com",
        "microsoft.com",
    ],
    "projects": ["Tax Season 2026", "Client Onboarding"],
    "loop_seed": 23,
    "scanned": 49,
    "employees": [
        {"name": "Grace Kim", "email": "grace.kim@ledgerline-cpa.com",
         "role": "Managing Partner", "manager": None},
        {"name": "Daniel Osei", "email": "daniel.osei@ledgerline-cpa.com",
         "role": "Bookkeeper", "manager": "Grace Kim"},
        {"name": "Lily Zhang", "email": "lily.zhang@ledgerline-cpa.com",
         "role": "Tax Associate", "manager": "Grace Kim"},
        {"name": "Raj Mehta", "email": "raj.mehta@ledgerline-cpa.com",
         "role": "Office Admin", "manager": "Grace Kim"},
    ],
    "inbox": [
        _email("l1", "Grace Kim", "grace.kim@ledgerline-cpa.com",
               "daniel.osei@ledgerline-cpa.com", "Client onboarding checklist",
               "Hi Daniel, can you prep the onboarding checklist for the two new clients "
               "before Friday? No rush today. Thanks, Grace"),
        _email("l2", "Grace Kim", "grace.kim@ledgerline-cpa.co",
               "daniel.osei@ledgerline-cpa.com", "Change client payment account - urgent",
               "Daniel, a client has changed their bank. Please update their payment "
               "account and send the next $23,000 remittance to the new details today. "
               "Keep this between us until I confirm. - Grace",
               spf="fail", dkim="none", dmarc="fail"),
        _email("l3", "TaxSoftPro Billing", "billing@taxsoftpr0.com",
               "raj.mehta@ledgerline-cpa.com", "Your license expires today",
               "Your TaxSoftPro license expires today and will lock during tax season. "
               "Renew now and verify your payment card here: https://bit.ly/tsp-renew .",
               spf="fail", dkim="fail", dmarc="fail"),
        _email("l4", "First National Bank", "statements@firstnational-bank.com",
               "grace.kim@ledgerline-cpa.com", "September statement ready",
               "Hi Grace, your September business statement is available in online "
               "banking. No action needed. First National Bank."),
        _email("l5", "Grace Kim", "grace.kim.partner@gmail.com",
               "raj.mehta@ledgerline-cpa.com", "Quick favour for Tax Season 2026",
               "Hi Raj, I'm in back-to-back meetings on Tax Season 2026. Can you buy "
               "$500 in gift cards for client thank-yous and send me the codes? I'll "
               "expense it. Keep it quick, thanks.",
               spf="fail", dkim="fail", dmarc="fail"),
        _email("l6", "LedgerLine Admin", "admin@ledgerline-cpa.com",
               "all@ledgerline-cpa.com", "Office notes - October",
               "Reminders: timesheets due Friday, the Client Onboarding drive is tidied "
               "up, and mince pies are back in the kitchen. Have a good month!"),
    ],
    "events": {
        "grace.kim@ledgerline-cpa.com": [
            {"action": "reported"}, {"action": "reported"}],
        "daniel.osei@ledgerline-cpa.com": [
            {"action": "clicked"}, {"action": "entered_data"}, {"action": "reported"}],
        "lily.zhang@ledgerline-cpa.com": [
            {"action": "reported"}, {"action": "ignored"}, {"action": "reported"}],
        "raj.mehta@ledgerline-cpa.com": [
            {"action": "clicked"}, {"action": "clicked"}, {"action": "ignored"}],
    },
}

CLIENTS = {c["id"]: c for c in (ACME, BRIGHTSMILE, LEDGERLINE)}

# Backward-compatible single-org handles used by the detector tests.
ORG = ACME


def list_clients():
    return list(CLIENTS.values())


def get_client(cid):
    return CLIENTS.get(cid)


def sample_inbox():
    return list(ACME["inbox"])


def seed_simulation_events():
    return ACME["events"]
