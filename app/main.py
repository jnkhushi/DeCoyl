"""DeCoyl MSP console: API + dashboard over several client tenants.

Run:  uvicorn app.main:app --reload
Then open http://127.0.0.1:8000
"""

from datetime import date
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from . import data, detector, llm, loop, report, scoring, simulator

app = FastAPI(title="DeCoyl MSP Console", version="0.2.0")
STATIC = Path(__file__).parent / "static"


class EmailIn(BaseModel):
    from_name: str = ""
    from_addr: str = ""
    subject: str = ""
    body: str = ""
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"


class SimIn(BaseModel):
    employee_email: str
    difficulty: str = "medium"


def _client_or_404(cid):
    client = data.get_client(cid)
    if client is None:
        raise HTTPException(status_code=404, detail="unknown client")
    return client


def _analyze(email, client):
    """Heuristic analysis, with live Claude detection layered in when available."""
    result = detector.analyze(email, client)
    return llm.apply_claude(result, llm.assess(email))


def _summary(client):
    """Cheap risk rollup for one client (no loop; detector + scoring only)."""
    analyses = [detector.analyze(e, client) for e in client["inbox"]]
    emp = scoring.employee_scores(client["employees"], client["events"])
    avg_risk = round(sum(e["human_risk"] for e in emp) / len(emp)) if emp else 0
    dangerous = sum(1 for a in analyses if a["verdict"] == "dangerous")
    # Portfolio status: worst of inbox danger and employee risk.
    if dangerous or any(e["band"] == "high" for e in emp):
        band = "high"
    elif any(a["verdict"] == "suspicious" for a in analyses) or avg_risk >= 40:
        band = "medium"
    else:
        band = "low"
    return {
        "id": client["id"], "name": client["name"], "sector": client["sector"],
        "domain": client["domain"], "employees": len(client["employees"]),
        "scanned": client.get("scanned", len(analyses)), "dangerous": dangerous,
        "suspicious": sum(1 for a in analyses if a["verdict"] == "suspicious"),
        "avg_human_risk": avg_risk, "band": band,
    }


@app.get("/")
def home():
    return FileResponse(STATIC / "landing.html")


@app.get("/console")
def console():
    return FileResponse(STATIC / "index.html")


@app.get("/report")
def report_page():
    return FileResponse(STATIC / "report.html")


@app.get("/api/clients")
def clients():
    """Portfolio view: a risk summary for every client in the MSP's book."""
    return {
        "detection_mode": "claude + heuristics" if llm.available() else "heuristics",
        "clients": [_summary(c) for c in data.list_clients()],
    }


@app.get("/api/clients/{cid}/inbox")
def inbox(cid: str):
    client = _client_or_404(cid)
    return [{**e, "analysis": _analyze(e, client)} for e in client["inbox"]]


@app.get("/api/clients/{cid}/employees")
def employees(cid: str):
    client = _client_or_404(cid)
    return scoring.employee_scores(client["employees"], client["events"])


@app.get("/api/clients/{cid}/stats")
def stats(cid: str):
    return _summary(_client_or_404(cid))


@app.post("/api/clients/{cid}/analyze")
def analyze_one(cid: str, email: EmailIn):
    client = _client_or_404(cid)
    record = {
        "from_name": email.from_name, "from_addr": email.from_addr,
        "subject": email.subject, "body": email.body,
        "auth": {"spf": email.spf, "dkim": email.dkim, "dmarc": email.dmarc},
    }
    return _analyze(record, client)


@app.post("/api/clients/{cid}/simulate")
def simulate(cid: str, req: SimIn):
    client = _client_or_404(cid)
    persona = next((e for e in client["employees"] if e["email"] == req.employee_email), None)
    if persona is None:
        raise HTTPException(status_code=404, detail="unknown employee")
    return simulator.generate(persona, req.difficulty, client)


@app.get("/api/clients/{cid}/loop")
def self_improving_loop(cid: str, rounds: int = 5):
    """Run the attacker -> defender -> retrain loop with this client's seed."""
    client = _client_or_404(cid)
    return loop.run_loop(rounds=rounds, seed=client["loop_seed"])


@app.get("/api/clients/{cid}/report")
def compliance_report(cid: str):
    """Audit / cyber-insurance report: protection, detection, training, risk trend."""
    client = _client_or_404(cid)
    loop_result = loop.run_loop(rounds=5, seed=client["loop_seed"])
    return report.build(client, loop_result, date.today().strftime("%B %Y"))
