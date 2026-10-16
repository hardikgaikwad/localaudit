"""Command-line interface: `localaudit scan PATH ...`."""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from . import __version__, llm, report, scanner
from .models import SEVERITIES, SEVERITY_RANK, severity_at_least, sort_findings, validate_severity

COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[90m",
          "bold": "\033[1m", "dim": "\033[2m", "green": "\033[32m", "reset": "\033[0m"}


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR") or not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.name == "nt":
        os.system("")  # enables ANSI escape processing in the Windows console
    return True


class Console:
    def __init__(self, stream=sys.stdout):
        self.stream = stream
        self.color = _use_color(stream)

    def c(self, text: str, style: str) -> str:
        return f"{COLORS[style]}{text}{COLORS['reset']}" if self.color else text

    def print(self, text: str = "") -> None:
        print(text, file=self.stream, flush=True)


def _severity_arg(value: str) -> str:
    try:
        return validate_severity(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _formats_arg(value: str) -> list[str]:
    formats = [v.strip().lower() for v in value.split(",") if v.strip()]
    bad = [f for f in formats if f not in report.FORMATS]
    if bad or not formats:
        raise argparse.ArgumentTypeError(f"unknown format(s) {bad}; choose from {','.join(report.FORMATS)}")
    return list(dict.fromkeys(formats))


def _positive_int(value: str) -> int:
    n = int(value)
    if n < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return n


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="localaudit", description="Local-only security audit for source code.")
    parser.add_argument("--version", action="version", version=f"localaudit {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument("--model", default=None,
                      help=f"Ollama model (default: $LOCALAUDIT_MODEL or {llm.DEFAULT_MODEL})")
    scan.add_argument("--out", default="localaudit-report", help="output directory (default: ./localaudit-report)")
    scan.add_argument("--no-llm", action="store_true", help="skip LLM triage; rules only")
    scan.add_argument("--max-llm-findings", type=_positive_int, default=25,
                      help="max findings sent to the LLM, highest severity first (default: 25)")
    scan.add_argument("--min-severity", type=_severity_arg, default="info",
                      help="drop findings below this severity (critical/high/medium/low/info)")
    scan.add_argument("--format", type=_formats_arg, default=list(report.FORMATS),
                      help="comma-separated output formats: html,json,md (default: all)")
    scan.add_argument("--fail-on", type=_severity_arg, default=None,
                      help="exit with code 1 if any finding is at or above this severity")
    return parser


def run_scan(args, out: Console, err: Console) -> int:
    target = Path(args.path)
    if not target.exists():
        err.print(f"error: path not found: {args.path}")
        return 2
    started = time.monotonic()
    model = args.model or llm.default_model()

    out.print(out.c(f"LocalAudit {__version__}", "bold") + f"  scanning {target.resolve()}")
    result = scanner.scan(target)
    findings = [f for f in result.findings if severity_at_least(f.severity, args.min_severity)]
    out.print(f"Scanned {result.files_scanned} files ({result.files_skipped} skipped), "
              f"{len(findings)} findings at or above '{args.min_severity}'.")
    for notice in result.notices:
        out.print(out.c(f"note: {notice}", "dim"))

    used_model = None
    if args.no_llm:
        llm_status = "disabled (--no-llm)"
    elif not findings:
        llm_status = "not needed (no findings)"
    elif args.max_llm_findings == 0:
        llm_status = "disabled (--max-llm-findings 0)"
    else:
        ok, message = llm.check_ollama(model)
        if not ok:
            err.print(err.c("warning: ", "medium") + message)
            llm_status = "unavailable (" + message.split(".")[0] + ")"
        else:
            used_model = model
            triager = llm.Triager(model)
            n = min(len(findings), args.max_llm_findings)
            out.print(f"Triaging {n} finding{'s' if n != 1 else ''} with {model} (local Ollama)...")
            interactive = err.stream.isatty() if hasattr(err.stream, "isatty") else False

            def progress(i: int, total: int, f) -> None:
                label = f"  [{i}/{total}] {f.rule_id} {f.file}:{f.line}"
                if interactive:
                    err.stream.write("\r" + label[:100].ljust(100))
                    err.stream.flush()
                else:
                    err.print(label)

            stats = llm.triage_findings(findings, triager, args.max_llm_findings, progress)
            if interactive:
                err.stream.write("\r" + " " * 100 + "\r")
                err.stream.flush()
            llm_status = (f"{stats['triaged']} triaged ({stats['cached']} from cache), {stats['failed']} failed, "
                          f"{stats['skipped']} over cap")
            if stats["aborted"]:
                err.print(err.c("warning: ", "medium") + "Ollama became unreachable during triage; "
                          "remaining findings were not triaged.")
                llm_status += ", aborted (Ollama unreachable)"
            out.print(f"LLM triage: {llm_status}")

    meta = {
        "path": str(target.resolve()),
        "date": datetime.now().astimezone().isoformat(timespec="seconds"),
        "model": used_model,
        "llm_status": llm_status,
        "duration_s": time.monotonic() - started,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "min_severity": args.min_severity,
        "notices": result.notices,
    }
    data = report.build_report_data(findings, meta)
    written = report.write_reports(data, args.out, args.format)

    print_summary(out, data)
    for path in written:
        out.print(f"  wrote {path}")

    if args.fail_on:
        failing = [f for f in findings if severity_at_least(f.severity, args.fail_on)]
        if failing:
            out.print(out.c(f"FAIL: {len(failing)} finding(s) at or above '{args.fail_on}'.", "critical"))
            return 1
    return 0


def print_summary(out: Console, data: dict) -> None:
    s = data["summary"]
    out.print()
    parts = [out.c(f"{s['counts'][sev]} {sev}", sev) for sev in SEVERITIES]
    out.print(out.c("Summary: ", "bold") + ", ".join(parts)
              + (f"  (+{s['likely_false_positives']} likely false positives)" if s["likely_false_positives"] else ""))
    score_style = "critical" if s["risk_score"] >= 75 else "high" if s["risk_score"] >= 50 else \
        "medium" if s["risk_score"] >= 20 else "green"
    out.print(out.c("Risk score: ", "bold") + out.c(f"{s['risk_score']}/100 ({s['risk_label']})", score_style))
    top = [f for f in sort_findings(data["findings"]) if SEVERITY_RANK[f.severity] >= SEVERITY_RANK["high"]][:10]
    if top:
        out.print(out.c("Top findings:", "bold"))
        for f in top:
            out.print(f"  {out.c(f.severity.upper().ljust(8), f.severity)} {f.file}:{f.line}  {f.title}")
    out.print()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    out, err = Console(sys.stdout), Console(sys.stderr)
    if args.command == "scan":
        return run_scan(args, out, err)
    return 2


if __name__ == "__main__":
    sys.exit(main())
