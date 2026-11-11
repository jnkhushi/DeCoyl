"""Optional live Claude detection layer.

The whole product runs on the heuristic detector (app/detector.py) with no
credentials. When ANTHROPIC_API_KEY is set, `assess()` asks Claude to judge an
email directly (phishing or not, a confidence, and a plain-English reason), and
`apply_claude()` folds that judgment into the heuristic result as an ensemble.

Design choices:
  * Claude JUDGES the email, it does not just rephrase the heuristic signals -
    that is what makes this real LLM detection, matching the paper's core claim.
  * The two detectors form an ensemble: a confident Claude "phishing" raises the
    risk score; a Claude "legitimate" never lowers a heuristic danger flag (we
    keep the safer verdict and surface the disagreement).
  * Any failure (no key, network, bad JSON) returns None and the heuristic result
    stands unchanged, so the app always works.
"""

import json
import os

from . import detector

MODEL = os.getenv("DECOYL_MODEL", "claude-opus-5-5")

_SCHEMA = {
    "type": "json_schema",
    "schema": {
        "type": "object",
        "properties": {
            "is_phishing": {"type": "boolean"},
            "confidence": {"type": "integer"},        # 0-100
            "reason": {"type": "string"},             # one or two plain sentences
        },
        "required": ["is_phishing", "confidence", "reason"],
        "additionalProperties": False,
    },
}


def available():
    """True if a Claude call could succeed (a key is configured)."""
    return bool(os.getenv("ANTHROPIC_API_KEY"))


def assess(email):
    """Ask Claude to judge one email. Returns {is_phishing, confidence, reason} or None."""
    if not available():
        return None
    try:
        import anthropic
    except ImportError:
        return None

    auth = email.get("auth", {})
    prompt = (
        "Decide whether this email is a phishing or business-email-compromise attempt. "
        "Judge the email itself - sender, intent, pressure, links, authentication. "
        "Give a confidence 0-100 and a reason in at most two plain sentences a "
        "non-technical employee would understand.\n\n"
        f"From: {email.get('from_name','')} <{email.get('from_addr','')}>\n"
        f"Subject: {email.get('subject','')}\n"
        f"Auth: SPF={auth.get('spf')} DKIM={auth.get('dkim')} DMARC={auth.get('dmarc')}\n"
        f"Body:\n{email.get('body','')}"
    )
    try:
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model=MODEL,
            max_tokens=400,
            output_config={"effort": "low", "format": _SCHEMA},
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(b.text for b in resp.content if b.type == "text")
        data = json.loads(text)
        return {
            "is_phishing": bool(data["is_phishing"]),
            "confidence": max(0, min(100, int(data["confidence"]))),
            "reason": str(data["reason"]).strip(),
            "model": resp.model,
        }
    except Exception:
        return None


def apply_claude(result, assessment):
    """Fold a Claude assessment into a heuristic result (ensemble). Pure, testable.

    assessment is the dict from assess(), or None. Returns the updated result.
    """
    if assessment is None:
        result["explained_by"] = "heuristic"
        return result

    result["claude"] = assessment
    result["explained_by"] = "claude"
    if assessment["is_phishing"]:
        # A confident Claude adds weight and can lift the verdict; it never lowers it.
        weight = round(assessment["confidence"] * 0.6)
        result["signals"].append({
            "layer": 5, "type": "claude", "weight": weight,
            "reason": f"Claude flags this as phishing ({assessment['confidence']}% "
                      f"confidence): {assessment['reason']}",
        })
        result["score"] = min(100, result["score"] + weight)
        result["verdict"] = detector._verdict(result["score"])
        result["explanation"] = assessment["reason"]
        result["advice"] = detector._advice(result["verdict"], result["signals"])
    # If Claude says legitimate, keep the heuristic verdict (safer) and leave the
    # heuristic explanation; the disagreement is visible in result["claude"].
    return result
