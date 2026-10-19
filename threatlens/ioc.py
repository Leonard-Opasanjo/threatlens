"""Indicator parsing: classify, refang and defang, normalise, extract from text, import files, deduplicate."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

TYPES = ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256")
_REFANG = [
    (re.compile(r"(?i)\bhxxps?(?=://)"), lambda m: m.group(0).lower().replace("hxxp", "http")),
    (re.compile(r"(?i)\s*\[\s*dot\s*\]\s*|\s*\(\s*dot\s*\)\s*|\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\[:\]"), ":"), (re.compile(r"\[@\]"), "@"), (re.compile(r"\[/\]"), "/"),
]
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
_HASHES = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_FIND = re.compile(
    r"(?P<url>\bhttps?://[^\s<>\"']+)"
    r"|(?P<hash>\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b)"
    r"|(?P<ipv4>\b(?:\d{1,3}\.){3}\d{1,3}\b)"
    r"|(?P<domain>\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b)", re.I)
_NOT_DOMAIN_TLD = {"txt", "log", "csv", "json", "exe", "dll", "py", "md", "html", "htm", "php", "js", "png", "jpg",
                   "pdf", "zip", "doc", "docx", "xls", "xlsx", "sh", "bat", "yml", "yaml", "conf", "cfg", "ini", "tmp",
                   "bak"}


@dataclass
class Indicator:
    type: str
    value: str                     # normalised form
    raw: str = ""                  # as submitted (possibly defanged)
    source: str = ""
    tags: list[str] = field(default_factory=list)
    first_seen: str = ""
    derived_from: str = ""         # key of the indicator this one was derived from (URL -> host)

    @property
    def key(self) -> str:
        return f"{self.type}:{self.value}"


def refang(text: str) -> str:
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


def defang(value: str, kind: str) -> str:
    """Make an indicator safe to paste into a report or chat without it becoming a working link."""
    if kind == "url":
        value = re.sub(r"^http", "hxxp", value, flags=re.I)
        p = urlsplit(value)
        host = (p.hostname or "").replace(".", "[.]")
        netloc = host + (f":{p.port}" if p.port else "")
        return urlunsplit((p.scheme, netloc, p.path, p.query, "")).replace("://", "[://]")
    if kind in ("domain", "ipv4"):
        return value.replace(".", "[.]")
    if kind == "ipv6":
        return value.replace(":", "[:]")
    return value


def classify(raw: str, source: str = "", tags: list[str] | None = None, first_seen: str = "") -> Indicator | None:
    """Turn one string into a typed, normalised indicator, or None when it is not one."""
    s = refang(raw.strip()).strip("'\"<>,; ")
    if "://" in s:
        s = s.rstrip(".,;:!?)]")  # sentence punctuation that the text extractor swept up
    if not s:
        return None
    if _HEX.match(s) and len(s) in _HASHES:
        return Indicator(_HASHES[len(s)], s.lower(), raw, source, list(tags or []), first_seen)
    try:
        ip = ipaddress.ip_address(s)
        return Indicator("ipv6" if ip.version == 6 else "ipv4", str(ip), raw, source, list(tags or []), first_seen)
    except ValueError:
        pass
    if "://" in s:
        p = urlsplit(s)
        if p.scheme.lower() in ("http", "https", "ftp") and p.hostname:
            netloc = p.hostname.lower() + (f":{p.port}" if p.port else "")
            if p.username:
                netloc = f"{p.username}:{p.password or ''}@{netloc}" if p.password else f"{p.username}@{netloc}"
            value = urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, ""))
            return Indicator("url", value, raw, source, list(tags or []), first_seen)
        return None
    d = s.lower().rstrip(".")
    if _DOMAIN.match(d) and d.rsplit(".", 1)[-1] not in _NOT_DOMAIN_TLD:
        return Indicator("domain", d, raw, source, list(tags or []), first_seen)
    return None


def host_of(ind: Indicator) -> Indicator | None:
    """The host of a URL as its own indicator (domain or IP), so analysts can pivot."""
    if ind.type != "url":
        return None
    host = urlsplit(ind.value).hostname or ""
    derived = classify(host, source="derived", tags=["derived-from-url"])
    if derived:
        derived.derived_from = ind.key
    return derived


def defang_text(text: str) -> str:
    """Defang every indicator found inside free text (used for report prose and source notes)."""
    raws = sorted({m.group(0) for m in _FIND.finditer(text)}, key=len, reverse=True)
    for raw in raws:
        ind = classify(raw)
        if ind:
            text = text.replace(raw, defang(raw if ind.type == "url" else ind.value, ind.type))
    return text


def extract(text: str, source: str = "") -> list[Indicator]:
    """Pull every indicator out of free text (defanged forms included)."""
    out: list[Indicator] = []
    for m in _FIND.finditer(refang(text)):
        ind = classify(m.group(0), source=source)
        if ind:
            out.append(ind)
    return dedupe(out)


def dedupe(indicators: list[Indicator]) -> list[Indicator]:
    merged: dict[str, Indicator] = {}
    for ind in indicators:
        if ind.key in merged:
            keep = merged[ind.key]
            keep.tags = sorted(set(keep.tags) | set(ind.tags))
            keep.source = keep.source or ind.source
            keep.first_seen = keep.first_seen or ind.first_seen
        else:
            merged[ind.key] = ind
    return list(merged.values())


_COLS = {"value": ("value", "indicator", "ioc", "observable"), "type": ("type", "kind"), "source": ("source", "feed"),
         "tags": ("tags", "labels"), "first_seen": ("first_seen", "firstseen", "date", "timestamp")}


def _col(row: dict, name: str) -> str:
    for candidate in _COLS[name]:
        for k, v in row.items():
            if k and k.strip().lower() == candidate and v:
                return ",".join(str(x) for x in v) if isinstance(v, (list, tuple)) else str(v).strip()
    return ""


def _from_row(row: dict, source: str) -> Indicator | None:
    value = _col(row, "value")
    if not value:
        return None
    tags = [t.strip() for t in re.split(r"[;,|]", _col(row, "tags")) if t.strip()]
    ind = classify(value, source=_col(row, "source") or source, tags=tags, first_seen=_col(row, "first_seen"))
    declared = _col(row, "type").lower()
    if ind and declared and declared not in (ind.type, "ip", "hash"):
        ind.tags = sorted(set(ind.tags) | {f"declared:{declared}"})
    return ind


def parse_csv(text: str, source: str = "") -> list[Indicator]:
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames and not any(_col({f: f for f in reader.fieldnames}, "value") for _ in [0]):
        # no header: treat every first column as the value
        rows = [{"value": r[0]} for r in csv.reader(io.StringIO(text)) if r]
    else:
        rows = list(reader)
    return dedupe([i for i in (_from_row(r, source) for r in rows) if i])


def parse_json(text: str, source: str = "") -> list[Indicator]:
    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get("indicators") or data.get("iocs") or data.get("data") or [data]
    if not isinstance(data, list):
        raise ValueError("JSON must be a list of indicator strings or objects")
    out = []
    for item in data:
        if isinstance(item, str):
            ind = classify(item, source=source)
        elif isinstance(item, dict):
            ind = _from_row(item, source)
        else:
            ind = None
        if ind:
            out.append(ind)
    return dedupe(out)


def parse_text(text: str, source: str = "") -> list[Indicator]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ind = classify(line, source=source)
        out += [ind] if ind else extract(line, source)
    return dedupe(out)


def load_file(path: str | Path, source: str = "") -> list[Indicator]:
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    if p.suffix.lower() == ".csv":
        return parse_csv(text, source or p.name)
    if p.suffix.lower() == ".json":
        return parse_json(text, source or p.name)
    return parse_text(text, source or p.name)
