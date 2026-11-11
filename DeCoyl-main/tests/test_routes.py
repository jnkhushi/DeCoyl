"""Route tests: landing page is the front door, console and report still serve."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_landing_is_the_front_page():
    r = client.get("/")
    assert r.status_code == 200
    body = r.text
    assert "DeCoyl" in body
    assert "/console" in body            # links into the demo
    assert "/report?client=acme" in body


def test_console_and_report_pages_serve():
    assert client.get("/console").status_code == 200
    assert "DeCoyl MSP Console" in client.get("/console").text   # the <title>
    assert client.get("/report").status_code == 200


def test_portfolio_api_lists_all_clients():
    data = client.get("/api/clients").json()
    assert {c["id"] for c in data["clients"]} == {"acme", "brightsmile", "ledgerline"}


def test_unknown_client_is_404():
    assert client.get("/api/clients/nope/inbox").status_code == 404
