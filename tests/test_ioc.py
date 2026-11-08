import pytest

from tests.conftest import SAMPLES
from threatlens.ioc import (
    classify,
    dedupe,
    defang,
    extract,
    host_of,
    load_file,
    parse_csv,
    parse_json,
    parse_text,
    refang,
)


def test_refang_and_defang():
    assert refang("hxxp://evil[.]example/x") == "http://evil.example/x"
    assert refang("203[.]0[.]113[.]45") == "203.0.113.45" and refang("evil (dot) example") == "evil.example"
    assert defang("http://evil.example:8080/x?y=1", "url") == "hxxp[://]evil[.]example:8080/x?y=1"
    assert defang("203.0.113.45", "ipv4") == "203[.]0[.]113[.]45" and defang("evil.example", "domain") == "evil[.]example"
    assert defang("abcd", "md5") == "abcd"
    # the lure before @ stays visible, and a URL or host inside the query is not left clickable
    assert (defang("http://google.com@malware-c2.example/login?u=https://x.example/p", "url")
            == "hxxp[://]google[.]com@malware-c2[.]example/login?u=https[://]x[.]example/p")


@pytest.mark.parametrize("value,kind", [
    ("203.0.113.45", "ipv4"), ("2001:db8::1", "ipv6"), ("evil.example", "domain"), ("xn--pple-43d.com", "domain"),
    ("http://evil.example/panel/gate.php?id=1", "url"), ("https://evil.example:8443/a?u=https://x.example/", "url"),
    ("ftp://203.0.113.45/drop.bin", "url"), ("http://user:pw@evil.example/", "url"), ("http://[2001:db8::1]:8080/x", "url"),
    ("0f3a7c1e2b9d4a6f8c0e1d2b3a4c5d6e", "md5"), ("5d41402abc4b2a76b9719d911017c592aa7b6c4d", "sha1"),
    ("9f2c0b4a8e6d1c3b5a7f9e0d2c4b6a8f1e3d5c7b9a0f2e4d6c8b0a1f3e5d7c9b", "sha256"),
])
def test_defang_refang_round_trip(value, kind):
    ind = classify(defang(value, kind))  # a ThreatLens report can be imported again without losing anything
    assert ind and ind.type == kind and ind.value == value


@pytest.mark.parametrize("raw,kind,value", [
    ("203.0.113.45", "ipv4", "203.0.113.45"),
    ("2001:db8::1", "ipv6", "2001:db8::1"),
    ("Evil.Example.", "domain", "evil.example"),
    ("xn--pple-43d.com", "domain", "xn--pple-43d.com"),
    ("HXXPS://Login-Update[.]example/Secure/verify#frag", "url", "https://login-update.example/Secure/verify"),
    ("http://203.0.113.45/update.exe", "url", "http://203.0.113.45/update.exe"),
    ("http://user:pw@evil.example:81/", "url", "http://user:pw@evil.example:81/"),
    ("0F3A7C1E2B9D4A6F8C0E1D2B3A4C5D6E", "md5", "0f3a7c1e2b9d4a6f8c0e1d2b3a4c5d6e"),
    ("5d41402abc4b2a76b9719d911017c592aa7b6c4d", "sha1", "5d41402abc4b2a76b9719d911017c592aa7b6c4d"),
    ("9f2c0b4a8e6d1c3b5a7f9e0d2c4b6a8f1e3d5c7b9a0f2e4d6c8b0a1f3e5d7c9b", "sha256", "9f2c0b4a8e6d1c3b5a7f9e0d2c4b6a8f1e3d5c7b9a0f2e4d6c8b0a1f3e5d7c9b"),
    ("hxxps[:]//evil[.]example", "url", "https://evil.example/"),
    ("fxp://evil[.]example/f", "url", "ftp://evil.example/f"),
    ("http://[2001:db8::1]:8080/x", "url", "http://[2001:db8::1]:8080/x"),  # brackets kept, so the port stays a port
    ("http://evil.example:80/x", "url", "http://evil.example/x"),  # default port: same URL as without it
    ("http://malware-c2.example\\@google.com/x", "url", "http://malware-c2.example/@google.com/x"),  # as browsers read it
    ("::ffff:203.0.113.45", "ipv4", "203.0.113.45"),
    ("bücher.de", "domain", "xn--bcher-kva.de"),
    ("evil.zip", "domain", "evil.zip"),  # .zip is a real top-level domain
])
def test_classify(raw, kind, value):
    ind = classify(raw)
    assert ind and ind.type == kind and ind.value == value and ind.key == f"{kind}:{value}"


@pytest.mark.parametrize("raw", ["", "not an indicator", "999.1.1.1", "file.txt", "ftp.example/x", "mailto:a@b.example",
                                 "0f3a7c1e2b9d", "localhost", "update.ps1", "svchost.scr", "report.rtf", "drop.bin",
                                 "https://evil.example:99999/", "http://evil.example:abc/", "http://[::1"])
def test_not_indicators(raw):
    assert classify(raw) is None


def test_bad_url_does_not_sink_the_batch():
    rows = parse_text("http://[2001:db8::1]:8080/x\nhttps://evil.example:99999/\n203.0.113.45\n")
    assert [r.key for r in rows] == ["url:http://[2001:db8::1]:8080/x", "ipv4:203.0.113.45"] and rows.skipped == 1
    assert host_of(rows[0]).key == "ipv6:2001:db8::1"


def test_extract_ipv6_ftp_and_file_names():
    found = {i.key for i in extract("Beacon to 2001:db8::5. At 12:30:45 ftp://203.0.113.7/a and invoice.zip, x.example")}
    assert found == {"ipv6:2001:db8::5", "url:ftp://203.0.113.7/a", "domain:x.example"}


def test_skipped_values_are_counted():
    rows = parse_csv("value,type\n203.0.113.0/24,ip\nbit.ly/3xmplz,url\n203.0.113.5:443,ip\n,ip\n")
    assert [r.key for r in rows] == ["url:http://bit.ly/3xmplz"] and rows[0].raw == "bit.ly/3xmplz"  # declared URL
    assert rows.skipped == 2  # the CIDR and the address with a port; the empty row is not a value
    assert parse_json('["evil.example", "nope", {"x": 1}]').skipped == 1
    assert parse_text("not-an-ioc\nprose with no indicator in it\n").skipped == 1


def test_host_of_and_dedupe():
    url = classify("http://203.0.113.45/update.exe")
    host = host_of(url)
    assert host.type == "ipv4" and host.value == "203.0.113.45" and host.derived_from == url.key
    assert host_of(classify("evil.example")) is None
    a = classify("evil.example", source="x", tags=["a"])
    b = classify("EVIL.example.", source="y", tags=["b"])
    merged = dedupe([a, b])
    assert len(merged) == 1 and merged[0].tags == ["a", "b"] and merged[0].source == "x"


def test_extract_from_text():
    text = ("Seen hxxp://malware-c2[.]example/panel/gate.php and 203[.]0[.]113[.]45, hash "
            "0f3a7c1e2b9d4a6f8c0e1d2b3a4c5d6e, domain payroll-portal[.]example; notes.txt is a file.")
    found = {i.key for i in extract(text)}
    assert found == {"url:http://malware-c2.example/panel/gate.php", "ipv4:203.0.113.45",
                     "md5:0f3a7c1e2b9d4a6f8c0e1d2b3a4c5d6e", "domain:payroll-portal.example"}


def test_parse_csv_json_text():
    rows = parse_csv((SAMPLES / "indicators.csv").read_text())
    assert len(rows) == 14
    url = next(r for r in rows if r.type == "url" and "gate.php" in r.value)
    assert url.source == "edr-alert-8810" and url.tags == ["c2"] and url.first_seen == "2026-10-17"
    assert parse_csv("203.0.113.45\nevil.example\n")[1].value == "evil.example"  # headerless
    rows = parse_json((SAMPLES / "indicators.json").read_text())
    keys = {r.key for r in rows}
    assert "ipv4:198.51.100.23" in keys and "domain:bit.ly" not in keys and "domain:mail.example.org" in keys
    assert next(r for r in rows if r.type == "sha1").source == "partner-share"
    assert next(r for r in rows if r.value == "198.51.100.23").tags == ["scanner"]  # JSON list tags stay tags
    assert parse_json('{"x": 1}') == []  # an object without a value field is simply not an indicator
    with pytest.raises(ValueError):
        parse_json("42")
    rows = parse_text((SAMPLES / "incident-notes.txt").read_text(), "notes")
    keys = {r.key for r in rows}
    assert {"url:http://malware-c2.example/panel/gate.php", "ipv4:203.0.113.45", "ipv4:198.51.100.77",
            "domain:xn--pple-43d.com", "domain:update.microsoft.com", "url:https://cdn-static.invalid/js/loader.js"} <= keys
    assert not any(r.value.endswith(".") for r in rows)  # sentence full stops are not part of a URL
    assert all(r.source == "notes" for r in rows)
    assert len(load_file(SAMPLES / "indicators.csv")) == 14
