import inspect
import json
import re
import subprocess
import sys

from tests.conftest import SAMPLES
from threatlens.cli import main


def test_dashboard_end_to_end(client):
    assert "ThreatLens" in client.get("/").text
    r = client.post("/import", data={"text": (SAMPLES / "incident-notes.txt").read_text(), "source": "notes", "fmt": "text"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/imports/1"
    page = client.get("/imports/1").text
    assert "hosts derived from URLs" in page and "malware-c2[.]example" in page and "offline" in page
    for h in ("content-security-policy", "x-frame-options"):
        assert h in client.get("/").headers
    rows = client.get("/api/indicators?verdict=malicious").json()
    assert rows and all(r["verdict"] == "malicious" for r in rows)
    ind = rows[0]
    detail = client.get(f"/indicators/{ind['id']}")
    assert detail.status_code == 200 and "Signals" in detail.text
    r = client.post(f"/indicators/{ind['id']}/status", data={"status": "confirmed", "note": "blocked"}, follow_redirects=False)
    assert r.status_code == 303 and client.get(f"/api/indicators/{ind['id']}").json()["status"] == "confirmed"
    assert client.post(f"/indicators/{ind['id']}/status", data={"status": "nope"}).status_code == 400
    listing = client.get("/indicators?verdict=malicious&q=malware").text
    assert "malware-c2[.]example" in listing
    md = client.get("/imports/1/report.md").text
    assert md.startswith("# Investigation report: notes") and "hxxp[://]" in md
    assert client.get("/report.md").status_code == 200 and client.get("/report.json").json()["count"] >= 5
    assert client.get("/api/stats").json()["imports"] == 1
    # upload a CSV file
    with open(SAMPLES / "indicators.csv", "rb") as fh:
        r = client.post("/import", data={"fmt": "auto"}, files={"file": ("indicators.csv", fh, "text/csv")},
                        follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/imports/2"
    assert client.get("/api/stats").json()["imports"] == 2
    assert client.get("/healthz").json() == {"ok": True}


def test_dashboard_rejects_bad_input(client):
    assert client.post("/import", data={"text": "", "fmt": "text"}).status_code == 400
    assert client.post("/import", data={"text": "nothing here", "fmt": "text"}).status_code == 400
    assert client.post("/import", data={"text": "{bad", "fmt": "json"}).status_code == 400
    assert client.get("/indicators/42").status_code == 404 and client.get("/imports/42").status_code == 404
    assert client.get("/imports/42/report.md").status_code == 404
    big = "x" * (5 * 1024 * 1024 + 1)
    assert client.post("/import", files={"file": ("big.txt", big, "text/plain")}).status_code == 413


def test_oversized_request_is_refused_before_the_form_is_read(client):
    from threatlens import web

    assert not inspect.iscoroutinefunction(web.do_import)  # imports run in the thread pool, not on the event loop
    r = client.post("/import", files={"file": ("big.txt", b"x" * (web.MAX_UPLOAD + 1024 * 1024 + 1), "text/plain")})
    assert r.status_code == 413 and r.headers["content-type"].startswith("text/plain")  # the middleware answered


def test_cross_site_requests_and_foreign_hosts_are_refused(client):
    form = {"text": "203.0.113.45", "fmt": "text"}
    for header in ({"origin": "https://attacker.example"}, {"origin": "null"}, {"referer": "https://attacker.example/"}):
        assert client.post("/import", data=form, headers=header).status_code == 403
    assert client.post("/import", data=form, headers={"origin": "http://localhost"}, follow_redirects=False).status_code == 303
    assert client.post("/indicators/1/status", data={"status": "false_positive"},
                       headers={"origin": "https://attacker.example"}).status_code == 403
    assert client.get("/api/indicators/1").json()["status"] == "new"
    assert client.get("/report.json", headers={"host": "rebind.attacker.example"}).status_code == 400  # DNS rebinding


def test_dashboard_pages_show_no_live_indicator(client):
    client.post("/import", data={"text": "http://malware-c2.example/panel/gate.php\nnot-an-ioc",
                                 "source": "see http://malware-c2.example/x", "fmt": "text"})
    pages = client.get("/").text + client.get("/imports/1").text + client.get("/indicators").text
    for row in client.get("/api/indicators").json():
        client.post(f"/indicators/{row['id']}/status", data={"status": "confirmed", "note": "blocked malware-c2.example"})
        page = client.get(f"/indicators/{row['id']}").text
        pages += re.sub(r'<input type="text" name="note"[^>]*>', "", page)  # the edit box keeps the note as typed
    assert "malware-c2.example" not in pages and "blocked malware-c2[.]example" in pages
    assert "1 skipped" in client.get("/imports/1").text


def test_api_docs_page_is_off_and_the_schema_is_linked(client):
    assert client.get("/api/docs").status_code == 404  # Swagger UI needs third-party scripts
    assert client.get("/api/openapi.json").json()["info"]["title"] == "ThreatLens"
    assert 'href="/api/openapi.json"' in client.get("/").text


def test_cli_exit_code_and_skipped_count(tmp_path, capsys):
    (tmp_path / "none.csv").write_text("value\n203.0.113.0/24\nnot-an-ioc\n")
    assert main(["analyse", str(tmp_path / "none.csv")]) == 2 and "2 skipped" in capsys.readouterr().err
    (tmp_path / "some.txt").write_text("203.0.113.45\nnot-an-ioc\n")
    assert main(["analyse", str(tmp_path / "some.txt")]) == 0 and "1 skipped" in capsys.readouterr().out


def test_cli_analyse_import_list_demo(tmp_path, capsys):
    rc = main(["analyse", str(SAMPLES / "indicators.csv"), "--report", str(tmp_path / "r.md"), "--json", str(tmp_path / "r.json")])
    out = capsys.readouterr().out
    assert rc == 0 and "indicators (" in out and "malicious" in out and "203[.]0[.]113[.]45" in out
    assert "203.0.113.45" not in out  # the CLI prints defanged values too
    assert "## Indicators requiring action" in (tmp_path / "r.md").read_text()
    assert json.loads((tmp_path / "r.json").read_text())["count"] >= 14
    db = tmp_path / "t.db"
    assert main(["import", str(SAMPLES / "indicators.json"), "--db", str(db), "--source", "partner", "--report", str(tmp_path / "i.md")]) == 0
    out = capsys.readouterr().out
    assert "import 1:" in out and "derived hosts" in out and (tmp_path / "i.md").read_text().startswith("# Investigation report: partner")
    assert main(["list", "--db", str(db), "--verdict", "malicious"]) == 0 and "indicators" in capsys.readouterr().out
    assert main(["demo", "--db", str(db)]) == 0 and "import 4:" in capsys.readouterr().out
    assert main(["analyse", str(tmp_path / "missing.csv")]) == 2
    (tmp_path / "empty.txt").write_text("nothing\n")
    assert main(["import", str(tmp_path / "empty.txt"), "--db", str(db)]) == 2


def test_module_entry_point():
    r = subprocess.run([sys.executable, "-m", "threatlens.cli", "--version"], capture_output=True, text=True)
    assert r.returncode == 0 and "threatlens 0." in r.stdout
