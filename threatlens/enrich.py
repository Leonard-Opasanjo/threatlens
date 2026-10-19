"""Enrichment sources and scoring. Offline by default: structural checks and local list feeds.
Feed downloads and DNS lookups run only when explicitly enabled, and nothing ever visits a URL."""

from __future__ import annotations

import ipaddress
import json
import math
import re
import socket
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .ioc import Indicator

FEEDS_DIR = Path(__file__).resolve().parent / "feeds"
VERDICTS = ("malicious", "suspicious", "benign", "unknown")
SEVERITIES = ("critical", "high", "medium", "low", "info")
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "work", "gq", "tk", "ml", "cf", "ga", "cam", "rest", "icu"}
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
EXEC_EXT = re.compile(r"\.(exe|scr|js|jse|hta|vbs|vbe|bat|cmd|ps1|msi|dll|jar|lnk|iso|img)(?:$|\?)", re.I)


@dataclass
class Signal:
    source: str
    verdict: str          # malicious | suspicious | benign | info
    weight: int
    note: str


@dataclass
class Score:
    verdict: str
    severity: str
    confidence: str
    reasons: list[str] = field(default_factory=list)


def _entropy(s: str) -> float:
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values()) if s else 0.0


class Structural:
    """Checks that need no data beyond the indicator itself."""

    name = "structural"

    def signals(self, ind: Indicator) -> list[Signal]:
        out: list[Signal] = []
        if ind.type in ("ipv4", "ipv6"):
            ip = ipaddress.ip_address(ind.value)
            if ip.version == 4 and any(ip in ipaddress.ip_network(n) for n in
                                       ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")):
                out.append(Signal(self.name, "info", 0, "Documentation range (RFC 5737): used in examples and tests."))
            elif ip.is_private or ip.is_loopback or ip.is_link_local:
                out.append(Signal(self.name, "info", 0, "Private or local address: not routable on the internet; "
                                                        "a match in a feed would be meaningless."))
            elif ip.is_reserved or ip.is_multicast:
                out.append(Signal(self.name, "info", 0, "Reserved or multicast address."))
        elif ind.type == "domain":
            out += self._domain(ind.value)
        elif ind.type == "url":
            p = urlsplit(ind.value)
            host = p.hostname or ""
            try:
                ipaddress.ip_address(host)
                out.append(Signal(self.name, "suspicious", 2, "URL uses a raw IP address instead of a host name."))
            except ValueError:
                out += self._domain(host)
            if p.username:
                out.append(Signal(self.name, "suspicious", 2, "URL carries credentials or a lookalike host before @."))
            if p.port and p.port not in (80, 443, 8080, 8443):
                out.append(Signal(self.name, "suspicious", 1, f"Uncommon port {p.port}."))
            if EXEC_EXT.search(p.path):
                out.append(Signal(self.name, "suspicious", 2, "Path ends in an executable or script file type."))
            if len(ind.value) > 200:
                out.append(Signal(self.name, "suspicious", 1, "Very long URL."))
            if host in SHORTENERS:
                out.append(Signal(self.name, "info", 0, "Link shortener: the destination is hidden."))
        return out

    def _domain(self, host: str) -> list[Signal]:
        out: list[Signal] = []
        labels = host.split(".")
        if any(label.startswith("xn--") for label in labels):
            out.append(Signal(self.name, "suspicious", 2,
                              "Internationalised (punycode) label: can imitate a known name."))
        if len(labels) >= 5:
            out.append(Signal(self.name, "suspicious", 1, f"Deeply nested host ({len(labels)} labels)."))
        if labels[-1] in RISKY_TLDS:
            out.append(Signal(self.name, "suspicious", 1, f"Top-level domain .{labels[-1]} is heavily abused."))
        longest = max(labels[:-1], key=len) if len(labels) > 1 else ""
        if len(longest) >= 12 and "-" not in longest and _entropy(longest) >= 3.3:
            vowels = sum(ch in "aeiou" for ch in longest) / len(longest)
            if vowels < 0.22 or re.search(r"[^aeiou]{5,}", longest):
                out.append(Signal(self.name, "suspicious", 2, f"Label '{longest}' looks machine-generated."))
        return out


class ListFeed:
    """A plain-text list of indicators from a local file or (opt-in) a trusted URL."""

    def __init__(self, name: str, kind: str, entries: set[str], verdict: str = "malicious", weight: int = 3,
                 description: str = ""):
        self.name, self.kind, self.entries, self.verdict, self.weight = name, kind, entries, verdict, weight
        self.description = description

    @staticmethod
    def parse(text: str) -> set[str]:
        out = set()
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            # hosts-file style "127.0.0.1 bad.example" -> keep the host
            parts = line.split()
            line = parts[-1] if len(parts) == 2 and parts[0] in ("127.0.0.1", "0.0.0.0") else parts[0]  # nosec B104: hosts-file syntax, not a bind address
            out.add(line.lower().rstrip("."))
        return out

    def _domain_hit(self, host: str) -> str | None:
        parts = host.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self.entries:
                return candidate
        return None

    def signals(self, ind: Indicator) -> list[Signal]:
        hit = None
        if self.kind == "ip" and ind.type in ("ipv4", "ipv6") and ind.value in self.entries:
            hit = ind.value
        elif self.kind == "domain" and ind.type == "domain":
            hit = self._domain_hit(ind.value)
        elif self.kind == "domain" and ind.type == "url":
            hit = self._domain_hit(urlsplit(ind.value).hostname or "")
        elif self.kind == "ip" and ind.type == "url" and (urlsplit(ind.value).hostname or "") in self.entries:
            hit = urlsplit(ind.value).hostname
        elif self.kind == "url" and ind.type == "url" and (ind.value in self.entries
                                                           or ind.value.rstrip("/") in self.entries):
            hit = ind.value
        elif self.kind == "hash" and ind.type in ("md5", "sha1", "sha256") and ind.value in self.entries:
            hit = ind.value
        if hit is None:
            return []
        what = "listed" if self.verdict != "benign" else "allow-listed"
        return [Signal(self.name, self.verdict, self.weight, f"{hit} is {what} in {self.name}"
                       + (f" ({self.description})" if self.description else ""))]


def load_feeds(config: str | Path | None = None, online: bool = False, cache_dir: str | Path | None = None,
               fetch=None) -> list[ListFeed]:
    """Feeds from feeds.json. Entries with a `path` are read locally; entries with a `url` are fetched only when
    `online` is true, through `fetch(url) -> str` (default: httpx GET with a timeout) and cached for a day."""
    config = Path(config) if config else FEEDS_DIR / "feeds.json"
    base = config.parent
    feeds: list[ListFeed] = []
    for entry in json.loads(config.read_text(encoding="utf-8")):
        if not entry.get("enabled", True):
            continue
        text = None
        if entry.get("path"):
            text = (base / entry["path"]).read_text(encoding="utf-8")
        elif entry.get("url"):
            if not online:
                continue
            text = _cached_fetch(entry["url"], entry["name"], cache_dir, fetch)
        if text is None:
            continue
        feeds.append(ListFeed(entry["name"], entry["kind"], ListFeed.parse(text), entry.get("verdict", "malicious"),
                              int(entry.get("weight", 3)), entry.get("description", "")))
    return feeds


def _cached_fetch(url: str, name: str, cache_dir, fetch) -> str:
    cache_dir = Path(cache_dir) if cache_dir else Path.home() / ".cache" / "threatlens"
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / (re.sub(r"[^a-z0-9]+", "-", name.lower()) + ".txt")
    if path.exists() and time.time() - path.stat().st_mtime < 86400:
        return path.read_text(encoding="utf-8")
    if fetch is None:
        import httpx

        def fetch(u: str) -> str:
            r = httpx.get(u, timeout=20, follow_redirects=True, headers={"User-Agent": "ThreatLens feed fetch"})
            r.raise_for_status()
            return r.text
    text = fetch(url)
    path.write_text(text, encoding="utf-8")
    return text


class Dns:
    """Opt-in DNS resolution. A lookup is not a visit, but it does reach resolvers; off by default."""

    name = "dns"

    def __init__(self, resolver=None):
        self.resolver = resolver or self._resolve

    @staticmethod
    def _resolve(ind: Indicator) -> list[str]:
        socket.setdefaulttimeout(5)
        if ind.type == "domain":
            return sorted({info[4][0] for info in socket.getaddrinfo(ind.value, None)})
        if ind.type in ("ipv4", "ipv6"):
            return [socket.gethostbyaddr(ind.value)[0]]
        return []

    def signals(self, ind: Indicator) -> list[Signal]:
        if ind.type not in ("domain", "ipv4", "ipv6"):
            return []
        try:
            results = self.resolver(ind)
        except (OSError, socket.herror, socket.gaierror) as e:
            return [Signal(self.name, "info", 0, f"Lookup failed: {e}")]
        if not results:
            return [Signal(self.name, "info", 0, "No record.")]
        label = "resolves to" if ind.type == "domain" else "reverse record"
        return [Signal(self.name, "info", 0, f"{label} {', '.join(results[:5])}")]


class Enricher:
    def __init__(self, sources: list | None = None):
        self.sources = sources if sources is not None else [Structural(), *load_feeds()]

    def enrich(self, ind: Indicator) -> list[Signal]:
        out: list[Signal] = []
        for source in self.sources:
            out += source.signals(ind)
        return out


def score(signals: list[Signal]) -> Score:
    malicious = [s for s in signals if s.verdict == "malicious"]
    suspicious = [s for s in signals if s.verdict == "suspicious"]
    benign = [s for s in signals if s.verdict == "benign"]
    mal_sources = {s.source for s in malicious}
    sus_weight = sum(s.weight for s in suspicious)
    reasons = [s.note for s in malicious + benign + suspicious]
    if sum(s.weight for s in malicious) >= 3:
        severity = "critical" if len(mal_sources) >= 2 else "high"
        confidence = "high" if len(mal_sources) >= 2 or sus_weight >= 2 else "medium"
        return Score("malicious", severity, confidence, reasons)
    if any(s.weight >= 3 for s in benign):
        return Score("benign", "low" if suspicious else "info",
                     "high" if not suspicious else "medium", reasons)
    if sus_weight >= 3:
        return Score("suspicious", "medium", "medium" if len({s.source for s in suspicious}) >= 2 else "low", reasons)
    if sus_weight >= 1:
        return Score("suspicious", "low", "low", reasons)
    return Score("unknown", "info", "low", reasons or ["No source had anything to say about this indicator."])
