from tests.conftest import FEEDS
from threatlens.enrich import Dns, Enricher, ListFeed, Signal, Structural, load_feeds, score
from threatlens.ioc import classify


def sigs(ind_text, sources=None):
    enr = Enricher(sources if sources is not None else [Structural(), *load_feeds(FEEDS / "feeds.json")])
    return enr.enrich(classify(ind_text))


def notes(ind_text):
    return [s.note for s in sigs(ind_text)]


def test_structural_ip_and_domain():
    assert any("Private" in n for n in notes("10.0.1.77")) and any("Documentation" in n for n in notes("192.0.2.10"))
    assert sigs("8.8.8.8", [Structural()]) == []
    assert any("punycode" in n for n in notes("xn--pple-43d.com"))
    assert any("machine-generated" in n for n in notes("akq9x2mz7vbh3qp.top")) and any(".top" in n for n in notes("akq9x2mz7vbh3qp.top"))
    assert any("Deeply nested" in n for n in notes("a.b.c.d.e.example"))
    assert sigs("update.microsoft.com", [Structural()]) == []


def test_structural_url():
    n = notes("http://198.51.100.200:8443/a.php")
    assert any("raw IP" in x for x in n) and not any("Uncommon port" in x for x in n)
    n = notes("https://cdn-assets-update.xyz:4443/dl/setup.exe")
    assert any("executable" in x for x in n) and any("Uncommon port" in x for x in n) and any(".xyz" in x for x in n)
    assert any("credentials" in x for x in notes("http://user:pw@evil.example/"))
    assert any("shortener" in x for x in notes("https://bit.ly/3xmplz"))


def test_feeds_match_including_subdomains_and_url_hosts():
    feeds = load_feeds(FEEDS / "feeds.json")
    assert {f.name for f in feeds} == {"local-malicious-ips", "local-malicious-domains", "local-malicious-urls",
                                       "local-malicious-hashes", "allowlist-domains"}  # online feeds skipped offline
    assert any(s.verdict == "malicious" for s in sigs("203.0.113.45"))
    assert any("files.payroll-portal.example" not in s.note and "payroll-portal.example is listed" in s.note
               for s in sigs("files.payroll-portal.example"))
    assert any(s.source == "local-malicious-domains" for s in sigs("http://malware-c2.example/other/path"))
    assert any(s.source == "local-malicious-urls" for s in sigs("http://malware-c2.example/panel/gate.php"))
    assert any(s.source == "local-malicious-ips" for s in sigs("http://203.0.113.45/update.exe"))
    assert any(s.verdict == "malicious" for s in sigs("0f3a7c1e2b9d4a6f8c0e1d2b3a4c5d6e"))
    assert any(s.verdict == "benign" for s in sigs("update.microsoft.com"))
    assert ListFeed.parse("# c\n0.0.0.0 bad.example\n127.0.0.1 worse.example # x\nEvil.Example.\n\n") == {"bad.example", "worse.example", "evil.example"}


def test_online_feed_fetch_is_opt_in_and_cached(tmp_path):
    calls = []

    def fetch(url):
        calls.append(url)
        return "203.0.113.250\n"
    offline = load_feeds(FEEDS / "feeds.json", online=False, cache_dir=tmp_path, fetch=fetch)
    assert calls == [] and not any(f.name == "feodo-tracker" for f in offline)
    online = load_feeds(FEEDS / "feeds.json", online=True, cache_dir=tmp_path, fetch=fetch)
    assert len(calls) == 2 and any(f.name == "feodo-tracker" and "203.0.113.250" in f.entries for f in online)
    load_feeds(FEEDS / "feeds.json", online=True, cache_dir=tmp_path, fetch=fetch)
    assert len(calls) == 2  # served from cache the second time


def test_feed_failure_is_reported_and_falls_back_to_the_stale_copy(tmp_path):
    import os

    import httpx
    import pytest

    def down(url):
        raise httpx.ConnectError("network unreachable")
    with pytest.raises(OSError, match="could not be downloaded"):  # what the CLI and the dashboard report
        load_feeds(FEEDS / "feeds.json", online=True, cache_dir=tmp_path, fetch=down)
    stale = tmp_path / "feodo-tracker.txt"
    stale.write_text("203.0.113.250\n")
    os.utime(stale, (0, 0))
    (tmp_path / "urlhaus-online.txt").write_text("")
    os.utime(tmp_path / "urlhaus-online.txt", (0, 0))
    feeds = load_feeds(FEEDS / "feeds.json", online=True, cache_dir=tmp_path, fetch=down)
    assert any(f.name == "feodo-tracker" and "203.0.113.250" in f.entries for f in feeds)


def test_allow_list_vouches_for_domains_not_urls():
    for url in ("https://raw.githubusercontent.com/a/x/main/stealer.ps1", "https://bucket.s3.amazonaws.com/inv.exe",
                "https://github.com/a/x/releases/download/v1/setup.exe", "http://malware-c2.example\\@google.com/x"):
        assert not any(s.verdict == "benign" for s in sigs(url)), url
    assert score(sigs("https://github.com/a/x/releases/download/v1/setup.exe")).verdict == "suspicious"
    assert score(sigs("http://malware-c2.example\\@google.com/x")).verdict == "malicious"
    assert score(sigs("github.com")).verdict == "benign"


def test_feed_entries_are_normalised_like_indicators():
    feed = ListFeed("custom", "url", ListFeed.parse("http://203.0.113.45/bins/Mozi.m\nhxxp://Evil[.]Example:80/x\n"))
    assert feed.signals(classify("http://203.0.113.45/bins/Mozi.m")) and feed.signals(classify("http://evil.example/x"))
    ips = ListFeed("ips", "ip", ListFeed.parse("2001:0db8:0000:0000:0000:0000:0000:0001\n198.18.0.0/15\n"))
    assert ips.signals(classify("2001:db8::1")) and ips.signals(classify("198.19.4.4"))
    assert ips.signals(classify("http://198.18.7.7/a")) and not ips.signals(classify("203.0.113.7"))
    assert any(s.source == "local-malicious-ips" for s in sigs("::ffff:203.0.113.45"))  # bundled list, mapped form


def test_dns_source_uses_injected_resolver():
    dns = Dns(resolver=lambda ind: ["203.0.113.5"])
    (s,) = dns.signals(classify("evil.example"))
    assert s.verdict == "info" and "resolves to 203.0.113.5" in s.note
    assert dns.signals(classify("0f3a7c1e2b9d4a6f8c0e1d2b3a4c5d6e")) == []

    def boom(ind):
        raise OSError("no network")
    assert "Lookup failed" in Dns(resolver=boom).signals(classify("evil.example"))[0].note


def test_score_table():
    mal = Signal("feed-a", "malicious", 3, "")
    mal2 = Signal("feed-b", "malicious", 3, "")
    sus2 = Signal("structural", "suspicious", 2, "")
    sus1 = Signal("structural", "suspicious", 1, "")
    ben = Signal("allow", "benign", 3, "")
    info = Signal("structural", "info", 0, "")
    assert (score([mal]).verdict, score([mal]).severity, score([mal]).confidence) == ("malicious", "high", "medium")
    assert (score([mal, mal2]).severity, score([mal, mal2]).confidence) == ("critical", "high")
    assert score([mal, sus2]).confidence == "high"
    assert (score([ben]).verdict, score([ben]).severity, score([ben]).confidence) == ("benign", "info", "high")
    assert (score([ben, sus1]).severity, score([ben, sus1]).confidence) == ("low", "medium")
    assert (score([sus2, sus1]).verdict, score([sus2, sus1]).severity) == ("suspicious", "medium")
    assert (score([sus1]).verdict, score([sus1]).severity) == ("suspicious", "low")
    assert (score([info]).verdict, score([info]).severity, score([]).verdict) == ("unknown", "info", "unknown")
