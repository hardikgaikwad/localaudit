"""Render scan results as self-contained HTML, JSON and Markdown."""

from __future__ import annotations

import json
import re
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from . import __version__
from .models import SEVERITIES, Finding, sort_findings

SEVERITY_WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
FORMATS = ("html", "json", "md")


def risk_score(findings: list[Finding]) -> int:
    """0-100, higher is riskier. Likely false positives (per LLM triage) do not count."""
    return min(100, sum(SEVERITY_WEIGHTS[f.severity] for f in findings if not f.likely_false_positive))


def risk_label(score: int) -> str:
    if score == 0:
        return "None"
    if score < 20:
        return "Low"
    if score < 50:
        return "Moderate"
    if score < 75:
        return "High"
    return "Critical"


def build_report_data(findings: list[Finding], meta: dict) -> dict:
    findings = sort_findings(findings)
    confirmed = [f for f in findings if not f.likely_false_positive]
    fps = [f for f in findings if f.likely_false_positive]
    counts = {s: sum(1 for f in confirmed if f.severity == s) for s in SEVERITIES}
    score = risk_score(findings)
    return {
        "tool": "LocalAudit",
        "version": __version__,
        "meta": meta,
        "summary": {
            "counts": counts,
            "total": len(confirmed),
            "likely_false_positives": len(fps),
            "risk_score": score,
            "risk_label": risk_label(score),
        },
        "findings": confirmed,
        "false_positives": fps,
    }


def _snippet_rows(f: Finding) -> list[dict]:
    return [
        {"num": f.snippet_start + i, "text": text, "hit": f.snippet_start + i == f.line}
        for i, text in enumerate(f.snippet.split("\n"))
    ]


def render_html(data: dict) -> str:
    env = Environment(loader=PackageLoader("localaudit", "templates"), autoescape=select_autoescape(["html", "j2"]))
    env.globals["snippet_rows"] = _snippet_rows
    template = env.get_template("report.html.j2")
    grouped = {s: [f for f in data["findings"] if f.severity == s] for s in SEVERITIES}
    return template.render(data=data, grouped=grouped, severities=SEVERITIES)


def render_json(data: dict) -> str:
    out = dict(data)
    out["findings"] = [f.to_dict() for f in data["findings"]]
    out["false_positives"] = [f.to_dict() for f in data["false_positives"]]
    return json.dumps(out, indent=2)


def _fence(code: str) -> str:
    longest = max((len(m) for m in re.findall(r"`+", code)), default=0)
    return "`" * max(3, longest + 1)


def _md_finding(f: Finding) -> list[str]:
    fence = _fence(f.snippet)
    out = [
        f"### [{f.severity.upper()}] {f.title}",
        "",
        f"- **Location:** `{f.file}:{f.line}`",
        f"- **Rule:** `{f.rule_id}`" + (f" ({f.cwe})" if f.cwe else ""),
        f"- **ID:** `{f.id}`",
        "",
        f.description,
        "",
        fence,
        f.snippet,
        fence,
        "",
    ]
    t = f.triage
    if t.available:
        out += [
            f"**Explanation:** {t.explanation}", "",
            f"**Risk in context:** {t.risk_in_context}", "",
            f"**LLM confidence:** {t.confidence}" + (" (likely false positive)" if t.likely_false_positive else ""), "",
            f"**Suggested fix:** {t.suggested_fix}", "",
        ]
        if t.fixed_code_example:
            fx = _fence(t.fixed_code_example)
            out += ["**Fix example:**", "", fx, t.fixed_code_example, fx, ""]
    elif t.note:
        out += [f"_{t.note}_", ""]
    return out


def render_markdown(data: dict) -> str:
    m, s = data["meta"], data["summary"]
    lines = [
        "# LocalAudit security report",
        "",
        f"- **Target:** `{m['path']}`",
        f"- **Date:** {m['date']}",
        f"- **Model:** {m['model'] or 'none (rules only)'}",
        f"- **LLM triage:** {m['llm_status']}",
        f"- **Duration:** {m['duration_s']:.1f}s",
        f"- **Files scanned:** {m['files_scanned']} (skipped {m['files_skipped']})",
        "",
        f"## Summary - risk score {s['risk_score']}/100 ({s['risk_label']})",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    lines += [f"| {sev} | {s['counts'][sev]} |" for sev in SEVERITIES]
    lines += [f"| likely false positives | {s['likely_false_positives']} |", ""]
    for notice in m.get("notices", []):
        lines.append(f"> {notice}")
    if m.get("notices"):
        lines.append("")
    lines += ["## Findings", ""]
    if not data["findings"]:
        lines += ["No findings.", ""]
    for f in data["findings"]:
        lines += _md_finding(f)
    if data["false_positives"]:
        lines += ["## Likely false positives", "",
                  "_The local LLM judged these likely false positives. They are kept for review, not deleted._", ""]
        for f in data["false_positives"]:
            lines += _md_finding(f)
    return "\n".join(lines)


def write_reports(data: dict, out_dir: str | Path, formats: list[str]) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    renderers = {"html": ("report.html", render_html), "json": ("report.json", render_json),
                 "md": ("report.md", render_markdown)}
    written = []
    for fmt in formats:
        name, render = renderers[fmt]
        path = out / name
        path.write_text(render(data), encoding="utf-8")
        written.append(path)
    return written
