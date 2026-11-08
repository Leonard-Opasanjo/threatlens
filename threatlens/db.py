"""SQLite store: imports, indicators (deduplicated across imports), their signals and analyst status."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from .enrich import SEVERITIES, VERDICTS, Enricher, Signal, score
from .ioc import Indicator, host_of

STATUSES = ("new", "investigating", "confirmed", "false_positive", "closed")
SCHEMA = """
CREATE TABLE IF NOT EXISTS imports (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, source TEXT NOT NULL DEFAULT '', at TEXT NOT NULL,
    total INTEGER NOT NULL DEFAULT 0, new INTEGER NOT NULL DEFAULT 0, updated INTEGER NOT NULL DEFAULT 0,
    derived INTEGER NOT NULL DEFAULT 0, online INTEGER NOT NULL DEFAULT 0, skipped INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY, type TEXT NOT NULL, value TEXT NOT NULL, raw TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '', tags_json TEXT NOT NULL DEFAULT '[]', first_seen TEXT NOT NULL DEFAULT '',
    last_seen TEXT NOT NULL, verdict TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new', note TEXT NOT NULL DEFAULT '', derived_from TEXT NOT NULL DEFAULT '',
    import_id INTEGER REFERENCES imports(id), times_seen INTEGER NOT NULL DEFAULT 1, UNIQUE(type, value));
CREATE TABLE IF NOT EXISTS signals (
    id INTEGER PRIMARY KEY, indicator_id INTEGER NOT NULL REFERENCES indicators(id), source TEXT NOT NULL,
    verdict TEXT NOT NULL, weight INTEGER NOT NULL, note TEXT NOT NULL, at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS import_items (
    import_id INTEGER NOT NULL REFERENCES imports(id), indicator_id INTEGER NOT NULL REFERENCES indicators(id),
    PRIMARY KEY (import_id, indicator_id));
CREATE INDEX IF NOT EXISTS signals_ind ON signals(indicator_id);
CREATE INDEX IF NOT EXISTS indicators_verdict ON indicators(verdict, severity);
"""
BY_SEVERITY = (" ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
               "WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        with self._conn() as c:
            c.executescript(SCHEMA)
            if "skipped" not in {r["name"] for r in c.execute("PRAGMA table_info(imports)")}:  # older databases
                c.execute("ALTER TABLE imports ADD COLUMN skipped INTEGER NOT NULL DEFAULT 0")

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON")
        return c

    # ingest ------------------------------------------------------------------------------------
    def ingest(self, indicators: list[Indicator], enricher: Enricher, name: str, source: str = "",
               online: bool = False) -> dict:
        batch = list(indicators)
        keys = {i.key for i in batch}
        derived = 0
        for ind in list(batch):
            host = host_of(ind)
            if host and host.key not in keys:
                batch.append(host)
                keys.add(host.key)
                derived += 1
        skipped = getattr(indicators, "skipped", 0)  # values the importer could not classify (ioc.Parsed)
        counts = {"total": len(batch), "new": 0, "updated": 0, "derived": derived, "skipped": skipped}
        sources = json.dumps([s.name for s in enricher.sources])
        with self._conn() as c:
            cur = c.execute("INSERT INTO imports (name, source, at, online, skipped) VALUES (?,?,?,?,?)",
                            (name[:200], source[:200], _now(), int(online), skipped))
            import_id = cur.lastrowid
            for ind in batch:
                signals = enricher.enrich(ind)
                existing = c.execute("SELECT id, tags_json, source, first_seen, times_seen FROM indicators "
                                     "WHERE type = ? AND value = ?", (ind.type, ind.value)).fetchone()
                if existing:
                    ind_id = existing["id"]
                    # replace what this run's sources say; keep the rest (an online feed's hit on an offline run)
                    c.execute("DELETE FROM signals WHERE indicator_id = ? AND source IN "
                              "(SELECT value FROM json_each(?))", (ind_id, sources))
                    kept = [Signal(**dict(r)) for r in c.execute("SELECT source, verdict, weight, note FROM signals "
                                                                 "WHERE indicator_id = ?", (ind_id,))]
                    sc = score(kept + signals)
                    tags = sorted(set(json.loads(existing["tags_json"])) | set(ind.tags))
                    c.execute("UPDATE indicators SET last_seen = ?, tags_json = ?, source = ?, first_seen = ?, "
                              "verdict = ?, severity = ?, confidence = ?, times_seen = times_seen + 1 WHERE id = ?",
                              (_now(), json.dumps(tags), existing["source"] or ind.source,
                               existing["first_seen"] or ind.first_seen, sc.verdict, sc.severity, sc.confidence,
                               ind_id))
                    counts["updated"] += 1
                else:
                    sc = score(signals)
                    cur = c.execute(
                        "INSERT INTO indicators (type, value, raw, source, tags_json, first_seen, last_seen, verdict, "
                        "severity, confidence, derived_from, import_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (ind.type, ind.value, ind.raw[:500], ind.source[:200], json.dumps(sorted(set(ind.tags))),
                         ind.first_seen[:40], _now(), sc.verdict, sc.severity, sc.confidence, ind.derived_from,
                         import_id))
                    ind_id = cur.lastrowid
                    counts["new"] += 1
                c.execute("INSERT OR IGNORE INTO import_items (import_id, indicator_id) VALUES (?,?)",
                          (import_id, ind_id))
                for s in signals:
                    c.execute("INSERT INTO signals (indicator_id, source, verdict, weight, note, at) "
                              "VALUES (?,?,?,?,?,?)", (ind_id, s.source, s.verdict, s.weight, s.note[:500], _now()))
            c.execute("UPDATE imports SET total = ?, new = ?, updated = ?, derived = ? WHERE id = ?",
                      (counts["total"], counts["new"], counts["updated"], derived, import_id))
        counts["import_id"] = import_id
        return counts

    # reads -------------------------------------------------------------------------------------
    @staticmethod
    def _row(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["tags"] = json.loads(d.pop("tags_json") or "[]")
        return d

    def list(self, type: str | None = None, verdict: str | None = None, severity: str | None = None,
             status: str | None = None, q: str | None = None, import_id: int | None = None,
             limit: int | None = 500) -> list[dict]:
        """Matching indicators, most severe first, then most recent; `limit=None` returns all of them."""
        where, params = [], []
        for col, val in (("type", type), ("verdict", verdict), ("severity", severity), ("status", status)):
            if val:
                where.append(f"{col} = ?")
                params.append(val)
        if q:
            where.append("(value LIKE ? OR tags_json LIKE ? OR note LIKE ?)")
            params += [f"%{q}%"] * 3
        if import_id:  # every indicator the import touched; imports made before import_items still show their new ones
            where.append("(import_id = ? OR id IN (SELECT indicator_id FROM import_items WHERE import_id = ?))")
            params += [import_id, import_id]
        # column names come from the fixed tuple above; every value is a bound parameter
        sql = "SELECT * FROM indicators" + (" WHERE " + " AND ".join(where) if where else "")  # nosec B608
        with self._conn() as c:
            return [self._row(r) for r in c.execute(sql + BY_SEVERITY + " LIMIT ?",
                                                    params + [-1 if limit is None else limit])]

    def get(self, ind_id: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM indicators WHERE id = ?", (ind_id,)).fetchone()
            if r is None:
                return None
            d = self._row(r)
            d["signals"] = [dict(s) for s in c.execute("SELECT source, verdict, weight, note, at FROM signals "
                                                       "WHERE indicator_id = ? ORDER BY id", (ind_id,))]
            key = f"{d['type']}:{d['value']}"
            related = [self._row(x) for x in c.execute("SELECT * FROM indicators WHERE derived_from = ? AND id != ?",
                                                       (key, ind_id))]
            if d["derived_from"]:
                t, _, v = d["derived_from"].partition(":")
                parent = c.execute("SELECT * FROM indicators WHERE type = ? AND value = ?", (t, v)).fetchone()
                if parent:
                    related.append(self._row(parent))
            if d["type"] in ("domain", "ipv4", "ipv6"):
                for x in c.execute("SELECT * FROM indicators WHERE type = 'url' AND id != ?", (ind_id,)):
                    if (urlsplit(x["value"]).hostname or "") == d["value"] and x["derived_from"] != key:
                        related.append(self._row(x))
            seen, uniq = set(), []
            for x in related:
                if x["id"] not in seen:
                    seen.add(x["id"])
                    uniq.append(x)
            d["related"] = uniq
            return d

    def set_status(self, ind_id: int, status: str, note: str = "") -> dict:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        with self._conn() as c:
            if c.execute("UPDATE indicators SET status = ?, note = ? WHERE id = ?",
                         (status, note.strip()[:2000], ind_id)).rowcount == 0:
                raise KeyError(ind_id)
        return self.get(ind_id)

    def stats(self) -> dict:
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
            imports = c.execute("SELECT COUNT(*) FROM imports").fetchone()[0]
            verdict = dict(c.execute("SELECT verdict, COUNT(*) FROM indicators GROUP BY verdict").fetchall())
            severity = dict(c.execute("SELECT severity, COUNT(*) FROM indicators GROUP BY severity").fetchall())
            kind = dict(c.execute("SELECT type, COUNT(*) FROM indicators GROUP BY type").fetchall())
            status = dict(c.execute("SELECT status, COUNT(*) FROM indicators GROUP BY status").fetchall())
        return {"total": total, "imports": imports, "verdict": {v: verdict.get(v, 0) for v in VERDICTS},
                "severity": {s: severity.get(s, 0) for s in SEVERITIES}, "type": kind,
                "status": {s: status.get(s, 0) for s in STATUSES}}

    def list_imports(self) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM imports ORDER BY id DESC")]

    def get_import(self, import_id: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM imports WHERE id = ?", (import_id,)).fetchone()
            return dict(r) if r else None

    def with_signals(self, rows: list[dict]) -> list[dict]:
        with self._conn() as c:
            for d in rows:
                d["signals"] = [dict(s) for s in c.execute("SELECT source, verdict, weight, note FROM signals "
                                                           "WHERE indicator_id = ? ORDER BY id", (d["id"],))]
        return rows
