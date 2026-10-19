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
