"""Synthetic email corpus for the self-improving loop.

Generates labelled phishing (1) and legitimate (0) emails from distinct tactic
families. Everything is fictional and training-only: links use the inert
example.com range, no real brands or payloads. These emails exist solely to
train and measure the detector inside the loop; nothing is ever sent.

Each phishing family has a distinctive vocabulary so a classifier must actually
learn that family to catch it, rather than relying on a few generic words.
"""

NAMES = ["Alex", "Sam", "Jordan", "Priya", "Chen", "Maria", "Tom", "Dana"]
COMPANIES = ["Globex", "Initech", "Umbrella", "Soylent", "Hooli"]


def _link(rng):
    return f"https://training.example.com/{rng.randint(1000, 9999)}"


# Phishing tactic families. Order matters: the loop seeds on the first few and
# introduces the rest one per round.
PHISH = {
    "bec_wire": {
        "subjects": ["Urgent payment needed", "Quick wire before 3pm",
                     "Confidential vendor payment"],
        "bodies": [
            "Hi {name}, I'm in a meeting and need you to wire {amount} to a new "
            "vendor right away. Keep this between us. - {sender}",
            "{name}, please process an urgent bank transfer of {amount} today. I'll "
            "send the account number next. Do not discuss this with anyone yet.",
            "Need a same-day wire of {amount} to close a deal. Confidential for now. "
            "Confirm once the transfer is sent, {name}.",
        ],
    },
    "credential": {
        "subjects": ["Verify your password now", "Account access expiring",
                     "Security alert: confirm login"],
        "bodies": [
            "Your email password expires today. Verify your account here to keep "
            "access: {link} . Sign in to confirm your credentials, {name}.",
            "We detected a new login. Confirm your identity and reset your password "
            "immediately at {link} or your account will be locked.",
            "{name}, your mailbox credentials must be re-verified. Log in to confirm "
            "at {link} within 24 hours.",
        ],
    },
    "invoice": {
        "subjects": ["Overdue invoice", "Updated remittance details",
                     "Payment past due"],
        "bodies": [
            "Hi {name}, invoice from {company} is overdue. We have updated our bank "
            "details - please send the outstanding {amount} to the new account: {link}",
            "Your account with {company} is past due. Remit {amount} today to avoid a "
            "late fee. Updated payment portal: {link}",
            "Reminder: {amount} outstanding to {company}. Note our remittance details "
            "have changed; pay via {link} .",
        ],
    },
    "giftcard": {
        "subjects": ["Quick favour", "Are you at your desk?", "Need your help"],
        "bodies": [
            "Hi {name}, are you free? I need you to buy five $100 gift cards for a "
            "client and send me the codes. I'll reimburse you later. - {sender}",
            "{name}, quick one - pick up some Apple gift cards for a staff reward and "
            "text me the numbers. Keep it discreet for the surprise.",
            "Busy in meetings - can you grab {amount} in gift cards and send the "
            "redemption codes? Will expense it. Thanks {name}.",
        ],
    },
    "delivery": {
        "subjects": ["Delivery failed", "Package on hold", "Reschedule your parcel"],
        "bodies": [
            "Your parcel could not be delivered. Pay a {amount} redelivery fee and "
            "confirm your address here: {link}",
            "{name}, we attempted delivery but no one was home. Reschedule your "
            "package within 48 hours at {link} or it will be returned.",
            "Shipment on hold pending a small customs charge. Clear it now: {link}",
        ],
    },
    "hr_benefits": {
        "subjects": ["Benefits enrollment closing", "Update your tax details",
                     "Payroll record change"],
        "bodies": [
            "Hi {name}, open enrollment ends today. Confirm your benefits and bank "
            "details for direct deposit here: {link}",
            "HR requires you to update your tax withholding before payroll runs. "
            "Complete the form at {link} to avoid a pay delay.",
            "{name}, we are updating payroll records. Verify your direct-deposit "
            "account at {link} this week.",
        ],
    },
    "it_storage": {
        "subjects": ["Mailbox almost full", "Storage limit reached",
                     "Email quota exceeded"],
        "bodies": [
            "Your mailbox is 98% full and will stop receiving email. Click to add "
            "storage: {link}",
            "{name}, your email quota is exceeded. Validate your account to restore "
            "sending at {link} .",
            "Storage upgrade required or messages will bounce. Re-activate here: {link}",
        ],
    },
    "prize": {
        "subjects": ["You have a refund waiting", "Claim your reward",
                     "Congratulations - action required"],
        "bodies": [
            "{name}, you are owed a {amount} refund. Confirm your card details to "
            "receive it: {link}",
            "You have won a reward in our staff raffle. Claim {amount} before it "
            "expires at {link} .",
            "A {amount} credit is pending on your account. Verify your bank info to "
            "release it: {link}",
        ],
    },
}

# Legitimate families (negatives). Plain business email, no links to act on.
HAM = {
    "meeting": {
        "subjects": ["Lunch Friday?", "Sync tomorrow", "Meeting moved"],
        "bodies": [
            "Hi {name}, are you free for a team lunch on Friday? Let me know. - {sender}",
            "Can we move our 1:1 to tomorrow at 2pm? Works better around the standup.",
            "{name}, the planning meeting is now in room B. See you there.",
        ],
    },
    "project": {
        "subjects": ["Project update", "Status for this week", "Sprint notes"],
        "bodies": [
            "Hi {name}, this week we finished the migration test and started on "
            "reporting. Nothing blocking. - {sender}",
            "Quick update: the design review went well, next step is the rollout plan.",
            "Notes from standup attached in the usual folder. Good progress overall.",
        ],
    },
    "invoice_ok": {
        "subjects": ["Invoice for October", "Monthly statement", "Receipt attached"],
        "bodies": [
            "Hi {name}, please find October's invoice from {company} attached, due "
            "net 30 as usual. Any questions let me know.",
            "Your monthly statement from {company} is ready in the portal you already "
            "use. No action needed.",
            "Thanks for your payment - receipt attached for your records.",
        ],
    },
    "newsletter": {
        "subjects": ["October newsletter", "Team highlights", "This month at work"],
        "bodies": [
            "This month: the office move is done, new starters in support, and a "
            "reminder to book your leave. Have a great month!",
            "Highlights: customer win with {company}, charity day photos, and the "
            "canteen menu refresh.",
            "{name}, catch up on this month's announcements in the internal blog.",
        ],
    },
    "colleague": {
        "subjects": ["Re: that doc", "Thanks!", "Quick question"],
        "bodies": [
            "Thanks {name}, that looks good. I'll add my comments by end of day.",
            "Do you have the latest figures for the review? No rush, tomorrow is fine.",
            "Great work on the demo today - the client was impressed. - {sender}",
        ],
    },
    "docshare": {
        "subjects": ["Shared: Q3 plan", "Doc for review", "Draft attached"],
        "bodies": [
            "Hi {name}, I've shared the Q3 plan in our team drive. Have a look when "
            "you get a chance.",
            "Draft of the proposal attached. Comments welcome, no deadline yet.",
            "Added you to the roadmap doc - same folder as last time.",
        ],
    },
}

PHISH_FAMILIES = list(PHISH)
HAM_FAMILIES = list(HAM)


def _fill(template, rng):
    return template.format(
        name=rng.choice(NAMES),
        sender=rng.choice(NAMES),
        company=rng.choice(COMPANIES),
        amount=f"${rng.randint(2, 80)},{rng.randint(100, 999)}",
        link=_link(rng),
    )


def _variants(spec, part):
    """Split a family's templates so train and test use different wording.

    'train' gets the first two variants, 'test' the last. This makes the loop's
    measurement genuine generalization, not memorization of shared phrasing.
    """
    subs, bods = spec["subjects"], spec["bodies"]
    if part == "train":
        return subs[:2], bods[:2]
    if part == "test":
        return subs[2:] or subs[-1:], bods[2:] or bods[-1:]
    return subs, bods


def _sample(groups, family, rng, part):
    subs, bods = _variants(groups[family], part)
    return f"{_fill(rng.choice(subs), rng)}\n{_fill(rng.choice(bods), rng)}"


def gen_phish(families, n_each, rng, part="all"):
    """Return [(text, 1), ...] for the given phishing families."""
    return [(_sample(PHISH, f, rng, part), 1) for f in families for _ in range(n_each)]


def gen_ham(n_each, rng, part="all"):
    """Return [(text, 0), ...] across all legitimate families."""
    return [(_sample(HAM, f, rng, part), 0) for f in HAM_FAMILIES for _ in range(n_each)]
