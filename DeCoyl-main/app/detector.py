"""The defender: four layers that score an inbound email for phishing risk.

Layer 1  language / pressure cues (urgency, authority, secrecy, payment, ...)
Layer 2  link and sender forensics (lookalike domains, auth results, bad URLs)
Layer 3  spear-phishing detector (internal specifics from an outside sender)
Layer 4  combine into a 0-100 score, a verdict, and plain-English reasons

Each layer emits "signals". A signal is a dict:
    {"layer": int, "type": str, "weight": int, "reason": str}

Detection here is heuristic so the demo runs with no API key. An optional LLM
layer (app/llm.py) can sharpen the explanation when a key is present.
"""

import re

# --- Layer 1: pressure-tactic keyword groups ---------------------------------
# Each group has a weight and the phrases that trigger it. Matching is on word
# boundaries, case-insensitive.
PRESSURE_GROUPS = {
    "urgency": (10, [
        "urgent", "immediately", "right away", "asap", "as soon as possible",
        "within the hour", "before 3pm", "by end of day", "time-sensitive",
        "act now", "expires today", "last warning",
    ]),
    "authority": (10, [
        "the ceo", "the owner", "as your manager", "on behalf of the", "i need you to",
        "do this now", "as a director",
    ]),
    "secrecy": (15, [
        "confidential", "between us", "keep this quiet", "don't tell", "do not discuss",
        "discreet", "keep this to yourself",
    ]),
    "payment": (15, [
        "wire", "wire transfer", "bank details", "account number", "gift card",
        "remittance", "invoice payment", "send payment", "bitcoin", "crypto",
    ]),
    "credential": (15, [
        "verify your account", "verify your password", "reset your password",
        "confirm your credentials", "sign in to confirm", "log in to verify",
        "mfa code", "one-time code", "verification code",
    ]),
    "lure": (8, [
        "click here", "click the link", "download the attachment",
        "open the attachment", "review the document", "confirm now",
    ]),
}

# --- Layer 2: forensics reference data ---------------------------------------
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
SUSPICIOUS_TLDS = {".zip", ".xyz", ".top", ".click", ".country", ".gq", ".work", ".mov"}
# Common homoglyph swaps attackers use to fake a trusted domain.
HOMOGLYPHS = {"0": "o", "1": "l", "3": "e", "5": "s", "rn": "m", "vv": "w"}

_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
_WORD_SPLIT = re.compile(r"[^a-z0-9]+")


def _levenshtein(a, b):
    """Edit distance between two short strings (iterative DP, no dependency)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def _host_of(addr_or_url):
    """Extract the host from an email address or a URL, lowercased."""
    s = addr_or_url.strip().lower()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]          # drop any path
    if "@" in s:
        s = s.rsplit("@", 1)[1]     # drop local part of an email
    return s.split(":", 1)[0]       # drop any port


def _dehomoglyph(host):
    out = host
    for bad, good in HOMOGLYPHS.items():
        out = out.replace(bad, good)
    return out


def _brand(domain):
    """The registrable brand token: label before the first dot, deglyphed, hyphenless.

    e.g. 'rnicrosoft-support.com' -> 'microsoftsupport', 'acme-corp.com' -> 'acmecorp'.
    """
    return _dehomoglyph(domain.split(".")[0]).replace("-", "")


def _lookalike_of(host, trusted_domains):
    """Return the trusted domain this host is impersonating, or None.

    Catches three techniques: homoglyph swaps (rn->m, 0->o), one/two-character
    typos, and a trusted brand padded with extra words (microsoft-support.com).
    Brand-substring matching can over-flag an unrelated domain that happens to
    contain the brand; acceptable for a prototype, tightened in production with a
    curated brand list and domain-age checks.
    """
    if host in trusted_domains:
        return None
    deglyphed = _dehomoglyph(host)
    host_brand = _brand(host)
    for trusted in trusted_domains:
        if deglyphed == trusted or deglyphed == _dehomoglyph(trusted):
            return trusted
        # Similar-length typosquat (acrne-corp.com vs acme-corp.com).
        if abs(len(host) - len(trusted)) <= 2 and _levenshtein(host, trusted) <= 2:
            return trusted
        # Trusted brand embedded in a longer domain with extra words.
        tb = _brand(trusted)
        if len(tb) >= 5 and tb != host_brand and tb in host_brand:
            return trusted
    return None


def _text(email):
    return f"{email.get('subject', '')}\n{email.get('body', '')}"


def layer1_language(email):
    """Pressure-tactic cues in subject + body."""
    text = _text(email).lower()
    signals = []
    for group, (weight, phrases) in PRESSURE_GROUPS.items():
        hits = [p for p in phrases if p in text]
        if hits:
            signals.append({
                "layer": 1, "type": group, "weight": weight,
                "reason": f"Language shows {group} ({', '.join(hits[:3])}).",
            })
    return signals


def layer2_forensics(email, org):
    """Lookalike domains, sender authentication, and risky links."""
    signals = []
    trusted = set(org.get("trusted_domains", []))
    sender_host = _host_of(email.get("from_addr", ""))

    # Sender domain impersonating a trusted one.
    look = _lookalike_of(sender_host, trusted)
    if look:
        signals.append({
            "layer": 2, "type": "sender_lookalike", "weight": 30,
            "reason": f"Sender domain '{sender_host}' mimics trusted '{look}'.",
        })

    # Display name is a known person but the address is external.
    from_name = email.get("from_name", "").strip().lower()
    known_names = {e["name"].lower() for e in org.get("employees", [])}
    if from_name in known_names and sender_host not in trusted:
        signals.append({
            "layer": 2, "type": "display_name_spoof", "weight": 30,
            "reason": f"Shows a known name ('{email['from_name']}') but an outside "
                      f"address ({email.get('from_addr')}).",
        })

    # Authentication results from the headers.
    auth = email.get("auth", {})
    failed = [k.upper() for k in ("spf", "dkim", "dmarc")
              if auth.get(k) in ("fail", "none")]
    if failed:
        signals.append({
            "layer": 2, "type": "auth_fail", "weight": min(10 * len(failed), 20),
            "reason": f"Sender authentication failed: {', '.join(failed)}.",
        })

    # Links in the body.
    for url in _URL_RE.findall(email.get("body", "")):
        host = _host_of(url)
        if re.match(r"\d+\.\d+\.\d+\.\d+", host):
            signals.append({"layer": 2, "type": "url_ip", "weight": 25,
                            "reason": f"Link points to a raw IP address ({host})."})
        elif host in SHORTENERS:
            signals.append({"layer": 2, "type": "url_shortener", "weight": 15,
                            "reason": f"Link uses a URL shortener ({host}) that hides "
                                      f"its real destination."})
        elif _lookalike_of(host, trusted):
            signals.append({"layer": 2, "type": "url_lookalike", "weight": 30,
                            "reason": f"Link host '{host}' mimics a trusted domain."})
        elif any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            signals.append({"layer": 2, "type": "url_sus_tld", "weight": 12,
                            "reason": f"Link uses an unusual top-level domain ({host})."})
    return signals


def layer3_spearphish(email, org):
    """Internal specifics (names, projects) coming from an untrusted sender."""
    trusted = set(org.get("trusted_domains", []))
    sender_host = _host_of(email.get("from_addr", ""))
    auth = email.get("auth", {})
    external = sender_host not in trusted
    unauthenticated = any(auth.get(k) in ("fail", "none") for k in ("spf", "dkim", "dmarc"))
    if not (external or unauthenticated):
        return []

    text_words = set(_WORD_SPLIT.split(_text(email).lower()))
    referenced = []
    for emp in org.get("employees", []):
        for part in emp["name"].lower().split():
            if len(part) > 2 and part in text_words:
                referenced.append(emp["name"])
                break
    for proj in org.get("projects", []):
        if proj.lower() in _text(email).lower():
            referenced.append(proj)

    if referenced:
        uniq = list(dict.fromkeys(referenced))
        return [{
            "layer": 3, "type": "spearphish", "weight": 25,
            "reason": f"References internal details ({', '.join(uniq[:3])}) but comes "
                      f"from an outside or unauthenticated sender.",
        }]
    return []


def _verdict(score):
    if score >= 60:
        return "dangerous"
    if score >= 25:
        return "suspicious"
    return "safe"


def _advice(verdict, signals):
    if verdict == "safe":
        return "Looks legitimate. Stay alert as always."
    types = {s["type"] for s in signals}
    if {"payment"} & types:
        return ("Do not pay or share bank details. Verify the request with the sender "
                "in person or by a known phone number before acting.")
    if {"credential", "url_lookalike", "url_shortener"} & types:
        return ("Do not click links or enter your password. Open the service directly "
                "from your browser and report this email to IT.")
    if verdict == "dangerous":
        return "Do not act on this email. Report it to IT and delete it."
    return "Treat with caution. Verify the sender before taking any action."


def analyze(email, org):
    """Run all layers and return the combined result (layer 4)."""
    signals = (
        layer1_language(email)
        + layer2_forensics(email, org)
        + layer3_spearphish(email, org)
    )
    score = min(sum(s["weight"] for s in signals), 100)
    verdict = _verdict(score)
    top = sorted(signals, key=lambda s: s["weight"], reverse=True)
    if verdict == "safe" and not signals:
        explanation = "No phishing signals found in language, links, or sender."
    else:
        explanation = " ".join(s["reason"] for s in top[:3])
    return {
        "id": email.get("id"),
        "score": score,
        "verdict": verdict,
        "explanation": explanation,
        "advice": _advice(verdict, signals),
        "signals": signals,
    }
