# DeCoyl

AI phishing **defense + awareness training** for small businesses: a **defender**, a
safe **training simulator**, a self-improving **loop**, and an **MSP console** that
manages several client companies at once. Runs on synthetic demo data.

## MSP multi-tenant console

The dashboard is an **MSP console**: one screen for an IT provider that
protects several small-business clients. The **portfolio** shows every client with its
sector, dangerous-email count, average human-risk, and a status band. Selecting a client
drills into that client's own inbox, employee risk scores, training simulations, and
self-improving loop. Each client has its own domain, people, trusted senders and loop
seed, so detection and metrics are fully isolated per tenant.

Demo clients: **Acme Corp** (logistics), **BrightSmile Dental** (healthcare), and
**LedgerLine Accounting** — payments-heavy small-business segments.

## What it does

- **Defender** — scores every inbound email through four layers:
  1. Language / pressure cues (urgency, authority, secrecy, payment, credential lures)
  2. Link & sender forensics (lookalike domains, SPF/DKIM/DMARC, shorteners, raw IPs)
  3. Spear-phish detector — internal specifics (real names, projects) from an *outside* sender
  4. Combine into a 0–100 risk score, a verdict, and a plain-English explanation + advice
- **Human-risk scoring** — each employee gets a 0–100 risk score from how they
  reacted to past simulations (reporting lowers it, clicking raises it).
- **Training simulator** — generates a **safe, labelled** phishing-awareness test for a
  synthetic persona. Nothing is sent; links are inert `example.com` placeholders.
- **Self-improving loop** — a closed attacker/defender loop. An attacker introduces a new
  phishing tactic each round; the misses feed back into a learning detector (logistic
  regression over email text), which retrains. Detection rate and false-positive rate are
  measured each round on a **fixed held-out test set** against a **frozen baseline** that
  never learns. On the default run the learner climbs from ~34% to ~88% detection while
  the baseline stays flat at ~34%, at a 0% false-positive rate — real numbers from the
  classifier, not staged.
- **Live Claude detection** — when `ANTHROPIC_API_KEY` is set, Claude *judges* each email
  directly (phishing or not, a confidence, a plain-English reason) and its verdict is
  combined with the heuristic detector as an ensemble: a confident Claude "phishing" raises
  the risk score, a Claude "legitimate" never lowers a heuristic danger flag. With no key
  the heuristic detector carries everything, so the app always runs.
- **Compliance / insurance report** — a per-client, printable report (`/report?client=<id>`)
  with emails scanned and attacks caught, measured detection vs baseline and false-positive
  rate, staff training results, and a human-risk trend. Print to PDF or download the JSON.
  Turns security into audit evidence.
- **MSP dashboard** — client portfolio, the loop chart, inbox with per-email verdicts,
  employee risk bars, a paste-an-email analyzer, a simulation generator, and the report.

## Run it

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000 — the landing page tells the whole story (problem, solution,
live links). From there:

- **`/`** — landing page (problem, closed loop, what's built, business)
- **`/console`** — the MSP multi-tenant console (the live demo)
- **`/report?client=<id>`** — a printable per-client compliance report (`acme`,
  `brightsmile`, `ledgerline`)

### Tests

```bash
python -m pytest -q
```

## Detection mode

Detection runs on **heuristics** out of the box — no API key needed, so it works
offline. If `ANTHROPIC_API_KEY` is set, Claude also judges each email directly and its
verdict is combined with the heuristic detector as an ensemble (`app/llm.py`); any
failure falls back to heuristics. Set the model with `DECOYL_MODEL` (default
`claude-opus-5-5`).

## Scope and honesty

- **All data is synthetic.** The demo company, employees, and emails are fictional;
  malicious samples use lookalikes of a made-up domain.
- **The simulator only produces training content** for synthetic personas, always
  labelled, never deployable against real people. It is a safe, consented red-team,
  not an attack tool.
- Heuristic detection (the live inbox) is a stand-in for a production classifier; real
  detection and false-positive rates would be measured in pilots.
- The self-improving loop trains a real ML classifier on synthetic tactic families. Its
  curve measures recall on **held-out instances** of each tactic (fresh names, amounts,
  links, and different wording than training) — honest generalization, not memorization,
  but still on synthetic mail. Pilot numbers will come from real inboxes.

## Layout

```
app/
  data.py        multi-tenant client registry (orgs, inboxes, events, loop seeds)
  detector.py    the four-layer defender
  scoring.py     human-risk scoring
  simulator.py   safe, labelled training-email generator
  corpus.py      synthetic phishing/legit tactic families for the loop
  loop.py        the self-improving loop (train, retrain, measure vs baseline)
  llm.py         live Claude detection + ensemble merge (dormant without a key)
  report.py      per-client compliance / insurance report builder
  main.py        FastAPI API + serves the dashboard and report page
  static/        dashboard (index.html) + printable report (report.html)
tests/           detector, scoring, loop, simulator-safety, client, llm, report, route tests
```
