"""The investigation report: Markdown with every indicator defanged, and a JSON export."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from . import __version__
from .enrich import SEVERITIES, VERDICTS
from .ioc import defang, defang_text

ACTION = {"malicious": "Block at the perimeter and DNS; search logs for any contact; treat hosts that reached it "
                       "as potentially compromised.",
          "suspicious": "Do not block on this alone. Check who or what referenced it, look it up in a second source, "
                        "and watch for further activity.",
          "benign": "No action. Listed as a well-known service; remove from the indicator set unless the full URL or "
                    "path is specific.",
          "unknown": "No source had information. Keep it in the watch-list and re-run enrichment later or add a "
                     "source."}


def investigation_report(indicators: list[dict], title: str = "ThreatLens investigation report",
                         generated: datetime | None = None, context: str = "") -> str:
    generated = generated or datetime.now(UTC)
    by_verdict = {v: [i for i in indicators if i["verdict"] == v] for v in VERDICTS}
    by_sev = {s: sum(1 for i in indicators if i["severity"] == s) for s in SEVERITIES}
    lines = [f"# {title}", "",
             f"Generated {generated:%Y-%m-%d %H:%M} UTC by ThreatLens {__version__} · {len(indicators)} indicators"
             + (f" · {context}" if context else ""), "",
             "All indicators in this report are defanged (`hxxp`, `[.]`) so they cannot be followed by accident.", ""]
    lines += ["## Summary", "", "| Verdict | Count |", "|---|---|"]
    lines += [f"| {v} | {len(by_verdict[v])} |" for v in VERDICTS]
    lines += ["", "| Severity | Count |", "|---|---|"] + [f"| {s} | {by_sev[s]} |" for s in SEVERITIES] + [""]

    action = [i for i in indicators if i["verdict"] in ("malicious", "suspicious")]
    lines += ["## Indicators requiring action", ""]
    if not action:
        lines.append("None.")
    else:
        lines += ["| Severity | Verdict | Confidence | Type | Indicator | Sources | Status |",
                  "|---|---|---|---|---|---|---|"]
        for i in action:
            sources = ", ".join(sorted({s["source"] for s in i.get("signals", []) if s["verdict"] != "info"}))
            sources = sources or "structural"
            lines.append(f"| {i['severity']} | {i['verdict']} | {i['confidence']} | {i['type']} | "
                         f"`{defang(i['value'], i['type'])}` | {sources} | {i.get('status', 'new')} |")
    lines.append("")

    lines += ["## Details", ""]
    for i in action:
        lines.append(f"### `{defang(i['value'], i['type'])}` ({i['type']}, {i['verdict']}, {i['severity']})")
        lines.append("")
        if i.get("tags"):
            lines.append(f"Tags: {', '.join(i['tags'])}  ")
        if i.get("source"):
            lines.append(f"Source: {i['source']}  ")
        if i.get("derived_from"):
            lines.append("Derived from a submitted URL.  ")
        for s in i.get("signals", []):
            lines.append(f"- **{s['verdict']}** ({s['source']}): {defang_text(s['note'])}")
        lines.append(f"- Recommended: {ACTION[i['verdict']]}")
        if i.get("note"):
            lines.append(f"- Analyst note: {i['note']}")
        lines.append("")

    others = by_verdict["benign"] + by_verdict["unknown"]
    if others:
        lines += ["## Benign and unknown", "", "| Verdict | Type | Indicator | Note |", "|---|---|---|---|"]
        for i in others:
            note = next((s["note"] for s in i.get("signals", []) if s["verdict"] in ("benign", "info")), "")
            lines.append(f"| {i['verdict']} | {i['type']} | `{defang(i['value'], i['type'])}` | {defang_text(note)} |")
        lines.append("")

    lines += ["## Method and limits", "",
              "Each indicator was normalised (defanged forms restored, case folded, URLs reduced to scheme, host, "
              "path and query) and checked against the configured sources: structural heuristics that need no data "
              "beyond the indicator itself, local list feeds, and any online feeds or DNS lookups that were enabled "
              "for this run. A malicious verdict needs a list match; a suspicious verdict comes from heuristics and "
              "should be confirmed with a second source; benign means the name is a well-known service, not that the "
              "full URL is safe. ThreatLens never visits a URL or opens a file, so content-based verdicts are out of "
              "scope. Confidence reflects how many independent sources agree.", ""]
    return "\n".join(lines) + "\n"


def to_json(indicators: list[dict], generated: datetime | None = None) -> str:
    generated = generated or datetime.now(UTC)
    return json.dumps({"tool": "threatlens", "version": __version__,
                       "generated": generated.isoformat(timespec="seconds"), "count": len(indicators),
                       "indicators": indicators}, indent=2, default=str)
