"""Command line: import files into the store, analyse files statelessly, list, serve, demo."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .enrich import Dns, Enricher, Structural, load_feeds, score
from .ioc import dedupe, defang, host_of, load_file
from .report import investigation_report, to_json

SAMPLES = Path(__file__).resolve().parent / "samples"


def _enricher(online: bool, feeds: str | None) -> Enricher:
    sources = [Structural(), *load_feeds(feeds, online=online)]
    if online:
        sources.append(Dns())
    return Enricher(sources)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="threatlens", description="Indicator of compromise analyser (offline by default)")
    p.add_argument("--version", action="version", version=f"threatlens {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("--online", action="store_true",
                        help="also fetch the configured online feeds and resolve DNS (never visits URLs)")
        sp.add_argument("--feeds", metavar="FEEDS.json", help="alternative feed configuration")

    a = sub.add_parser("analyse", help="analyse a CSV, JSON or text file without storing anything")
    a.add_argument("file")
    a.add_argument("--report", metavar="FILE.md")
    a.add_argument("--json", metavar="FILE.json")
    common(a)

    i = sub.add_parser("import", help="import a file into the database and enrich it")
    i.add_argument("file")
    i.add_argument("--source", default="", help="label for this batch (default: the file name)")
    i.add_argument("--db", default=os.environ.get("THREATLENS_DB", "threatlens.db"))
    i.add_argument("--report", metavar="FILE.md", help="write the investigation report for this batch")
    common(i)

    ls = sub.add_parser("list", help="list stored indicators")
    ls.add_argument("--db", default=os.environ.get("THREATLENS_DB", "threatlens.db"))
    ls.add_argument("--verdict", choices=["malicious", "suspicious", "benign", "unknown"])
    ls.add_argument("--type")

    s = sub.add_parser("serve", help="run the dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--db", default=os.environ.get("THREATLENS_DB", "threatlens.db"))

    d = sub.add_parser("demo", help="import the bundled sample files")
    d.add_argument("--db", default=os.environ.get("THREATLENS_DB", "threatlens.db"))
    return p


def _print(rows: list[dict]) -> None:
    for r in rows:
        src = ", ".join(sorted({s["source"] for s in r.get("signals", []) if s["verdict"] != "info"})) or "-"
        print(f"  {r['severity']:<8} {r['verdict']:<10} {r['confidence']:<6} {r['type']:<6} "
              f"{defang(r['value'], r['type'])}  [{src}]")


def analyse_cmd(args: argparse.Namespace) -> int:
    indicators = load_file(args.file)
    keys = {i.key for i in indicators}
    for ind in list(indicators):
        host = host_of(ind)
        if host and host.key not in keys:
            indicators.append(host)
            keys.add(host.key)
    indicators = dedupe(indicators)
    enr = _enricher(args.online, args.feeds)
    rows = []
    for ind in indicators:
        signals = enr.enrich(ind)
        sc = score(signals)
        rows.append({"type": ind.type, "value": ind.value, "raw": ind.raw, "source": ind.source, "tags": ind.tags,
                     "first_seen": ind.first_seen, "derived_from": ind.derived_from, "verdict": sc.verdict,
                     "severity": sc.severity, "confidence": sc.confidence, "status": "new", "note": "",
                     "signals": [s.__dict__ for s in signals]})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows.sort(key=lambda r: (order[r["severity"]], r["type"], r["value"]))
    counts = {v: sum(r["verdict"] == v for r in rows) for v in ("malicious", "suspicious", "benign", "unknown")}
    print(f"{args.file}: {len(rows)} indicators ({', '.join(f'{n} {v}' for v, n in counts.items() if n)})")
    _print(rows)
    if args.report:
        Path(args.report).write_text(investigation_report(rows, f"Investigation report: {Path(args.file).name}"),
                                     encoding="utf-8")
        print(f"report written to {args.report}")
    if args.json:
        Path(args.json).write_text(to_json(rows), encoding="utf-8")
        print(f"json written to {args.json}")
    return 0


def import_cmd(args: argparse.Namespace) -> int:
    from .db import Store

    db = Store(args.db)
    name = args.source or Path(args.file).name
    indicators = load_file(args.file, name)
    if not indicators:
        raise ValueError("no indicators found in the file")
    counts = db.ingest(indicators, _enricher(args.online, args.feeds), name, name, args.online)
    print(f"import {counts['import_id']}: {counts['total']} indicators, {counts['new']} new, "
          f"{counts['updated']} updated, {counts['derived']} derived hosts")
    rows = db.with_signals(db.list(import_id=counts["import_id"]))
    _print(rows)
    if args.report:
        Path(args.report).write_text(investigation_report(rows, f"Investigation report: {name}"), encoding="utf-8")
        print(f"report written to {args.report}")
    return 0


def list_cmd(args: argparse.Namespace) -> int:
    from .db import Store

    rows = Store(args.db).with_signals(Store(args.db).list(verdict=args.verdict, type=args.type))
    print(f"{len(rows)} indicators")
    _print(rows)
    return 0


def demo_cmd(args: argparse.Namespace) -> int:
    from .db import Store

    db = Store(args.db)
    enr = _enricher(False, None)
    for f in sorted(SAMPLES.iterdir()):
        counts = db.ingest(load_file(f, f.name), enr, f.name, f.name)
        print(f"import {counts['import_id']}: {f.name}: {counts['total']} indicators, {counts['new']} new")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "analyse":
            return analyse_cmd(args)
        if args.command == "import":
            return import_cmd(args)
        if args.command == "list":
            return list_cmd(args)
        if args.command == "demo":
            return demo_cmd(args)
        from .web import serve

        serve(args.host, args.port, args.db)
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
