import json
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
