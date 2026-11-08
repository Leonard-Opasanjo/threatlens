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
    assert c2["updated"] >= 1
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
    assert "hxxp[://]malware-c2[.]example/panel/gate[.]php" in md and "http://malware-c2.example" not in md
    assert "203[.]0[.]113[.]45" in md and "203.0.113.45" not in md
    assert md.index("## Indicators requiring action") < md.index("## Details") < md.index("## Benign and unknown") < md.index("## Method and limits")
    assert "| malicious |" in md and "google[.]com" in md and "Recommended: Block" in md
    doc = __import__("json").loads(to_json(rows))
    assert doc["tool"] == "threatlens" and doc["count"] == len(rows) and doc["indicators"][0]["signals"]
    assert "None." in investigation_report([r for r in rows if r["verdict"] == "unknown"])


def test_report_free_text_is_defanged_and_cannot_break_out_of_markdown(tmp_path):
    s = Store(tmp_path / "t.db")
    csv = ("value,source,tags\n203.0.113.45,partner https://malware-c2.example/p,see https://malware-c2.example/p\n"
           "http://203.0.113.9/x`[open](//malware-c2.example/p)`,feed,\nhttp://203.0.113.9/a|b,feed,\n")
    (tmp_path / "in.csv").write_text(csv)
    s.ingest(load_file(tmp_path / "in.csv"), enricher(), "https://malware-c2.example/ticket")
    s.set_status(1, "confirmed", "blocked http://malware-c2.example/p at the proxy")
    md = investigation_report(s.with_signals(s.list()), "Investigation report: https://malware-c2.example/ticket")
    assert "malware-c2.example" not in md and "://malware" not in md  # title, source, tags and note included
    assert "%60[open](//malware-c2[.]example/p)%60" in md and "a%7Cb" in md  # no code-span break-out, no extra column


def test_import_lists_only_what_that_import_touched(tmp_path):
    s = Store(tmp_path / "t.db")
    c1 = s.ingest(load_file(SAMPLES / "indicators.csv"), enricher(), "csv")
    c2 = s.ingest(load_file(SAMPLES / "indicators.json"), enricher(), "json")  # same second, overlapping hosts
    assert len(s.list(import_id=1)) == c1["total"] and len(s.list(import_id=2)) == c2["total"]
    assert "login-update.example" in {r["value"] for r in s.list(import_id=2)}  # seen before, still part of import 2


def test_database_from_before_import_items_still_opens(tmp_path):
    import sqlite3

    old = tmp_path / "old.db"
    with sqlite3.connect(old) as c:  # the 0.1.0 imports table: no skipped column, no import_items table
        c.execute("CREATE TABLE imports (id INTEGER PRIMARY KEY, name TEXT NOT NULL, source TEXT NOT NULL DEFAULT '', "
                  "at TEXT NOT NULL, total INTEGER NOT NULL DEFAULT 0, new INTEGER NOT NULL DEFAULT 0, "
                  "updated INTEGER NOT NULL DEFAULT 0, derived INTEGER NOT NULL DEFAULT 0, "
                  "online INTEGER NOT NULL DEFAULT 0)")
        c.execute("INSERT INTO imports (name, at) VALUES ('old', '2026-10-19T00:00:00+00:00')")
    s = Store(old)
    assert s.get_import(1)["skipped"] == 0 and s.list(import_id=1) == []
    assert s.ingest(load_file(SAMPLES / "indicators.csv"), enricher(), "new")["import_id"] == 2


def test_offline_reimport_keeps_what_an_online_feed_said(tmp_path):
    from threatlens.enrich import ListFeed
    from threatlens.ioc import classify

    s = Store(tmp_path / "t.db")
    online = Enricher([Structural(), *load_feeds(FEEDS / "feeds.json"), ListFeed("feodo-tracker", "ip", {"8.8.4.4"})])
    s.ingest([classify("8.8.4.4")], online, "online", online=True)
    s.ingest([classify("8.8.4.4")], enricher(), "offline")
    row = s.get(1)
    assert row["verdict"] == "malicious" and [x["source"] for x in row["signals"]] == ["feodo-tracker"]


def test_list_puts_severity_before_the_limit(tmp_path):
    from threatlens.ioc import classify

    s = Store(tmp_path / "t.db")
    s.ingest([classify("http://malware-c2.example/panel/gate.php")], enricher(), "old critical")
    s.ingest([classify(f"198.51.100.{i}") for i in range(1, 30)], Enricher([]), "newer noise")
    assert s.list(limit=5)[0]["severity"] == "critical" and len(s.list(limit=None)) == 31
