import pytest

from tests.conftest import FEEDS, SAMPLES
from threatlens.db import Store
from threatlens.enrich import Enricher, Structural, load_feeds
from threatlens.ioc import load_file
from threatlens.report import investigation_report, to_json


def enricher():
    return Enricher([Structural(), *load_feeds(FEEDS / "feeds.json")])


def test_ingest_dedupes_derives_and_rescores(tmp_path):
    s = Store(tmp_path / "t.db")
    c1 = s.ingest(load_file(SAMPLES / "indicators.csv", "csv"), enricher(), "csv")
    assert c1["new"] == c1["total"] and c1["derived"] >= 3 and c1["updated"] == 0
    rows = s.list()
    by = {r["value"]: r for r in rows}
    assert by["203.0.113.45"]["verdict"] == "malicious" and by["203.0.113.45"]["severity"] in ("high", "critical")
    assert by["http://malware-c2.example/panel/gate.php"]["severity"] == "critical"  # URL list + domain list agree
    assert by["google.com"]["verdict"] == "benign" and by["10.0.1.77"]["verdict"] == "unknown"
    assert by["xn--pple-43d.com"]["verdict"] == "suspicious"
    derived = by["malware-c2.example"]
    assert derived["derived_from"] == "url:http://malware-c2.example/panel/gate.php" and derived["verdict"] == "malicious"
    c2 = s.ingest(load_file(SAMPLES / "indicators.json", "json"), enricher(), "json")
    assert c2["updated"] >= 1  # 203.0.113.9 is in the CSV-derived set? no: it is new; login-update.example host is updated
    again = s.ingest(load_file(SAMPLES / "indicators.csv", "csv"), enricher(), "csv again")
    assert again["new"] == 0 and again["updated"] == again["total"]
    assert s.get(by["203.0.113.45"]["id"])["times_seen"] == 2
    stats = s.stats()
    assert stats["imports"] == 3 and stats["verdict"]["malicious"] >= 6 and stats["type"]["url"] >= 5
    assert [i["name"] for i in s.list_imports()] == ["csv again", "json", "csv"]
    assert s.get_import(1)["new"] == c1["total"] and s.get_import(99) is None


def test_get_related_status_and_filters(tmp_path):
    s = Store(tmp_path / "t.db")
    s.ingest(load_file(SAMPLES / "indicators.csv", "csv"), enricher(), "csv")
    url = next(r for r in s.list(type="url") if "gate.php" in r["value"])
    d = s.get(url["id"])
    assert [x["value"] for x in d["related"]] == ["malware-c2.example"] and d["signals"]
    host = s.get(d["related"][0]["id"])
    assert url["id"] in [x["id"] for x in host["related"]]
    assert s.list(verdict="malicious") and all(r["verdict"] == "malicious" for r in s.list(verdict="malicious"))
    assert all(r["severity"] == "critical" for r in s.list(severity="critical"))
    assert [r["value"] for r in s.list(q="payroll")] == ["files.payroll-portal.example"]
    updated = s.set_status(url["id"], "confirmed", "Blocked at proxy, ticket 4471")
    assert updated["status"] == "confirmed" and s.list(status="confirmed")[0]["id"] == url["id"]
    with pytest.raises(ValueError):
        s.set_status(url["id"], "bogus")
    with pytest.raises(KeyError):
        s.set_status(999, "closed")
    assert s.get(999) is None and s.list(import_id=1)


def test_report_is_defanged_and_structured(tmp_path):
    s = Store(tmp_path / "t.db")
    s.ingest(load_file(SAMPLES / "indicators.csv", "csv"), enricher(), "csv")
    rows = s.with_signals(s.list())
    md = investigation_report(rows, "Investigation report: csv", context="import 1")
    assert md.startswith("# Investigation report: csv") and "import 1" in md
    assert "hxxp[://]malware-c2[.]example/panel/gate.php" in md and "http://malware-c2.example" not in md
    assert "203[.]0[.]113[.]45" in md and "203.0.113.45" not in md
    assert md.index("## Indicators requiring action") < md.index("## Details") < md.index("## Benign and unknown") < md.index("## Method and limits")
    assert "| malicious |" in md and "google[.]com" in md and "Recommended: Block" in md
    doc = __import__("json").loads(to_json(rows))
    assert doc["tool"] == "threatlens" and doc["count"] == len(rows) and doc["indicators"][0]["signals"]
    assert "None." in investigation_report([r for r in rows if r["verdict"] == "unknown"])
