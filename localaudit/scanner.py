"""Walk a target path and run secret, code-pattern and dependency checks."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import secrets
from .models import Finding, sort_findings
from .rules import LANGUAGE_BY_EXT, rules_for

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
    ".localaudit_cache", "localaudit-report", ".pytest_cache", ".mypy_cache", ".tox",
}
BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz",
    ".7z", ".rar", ".jar", ".war", ".class", ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".pyc", ".pyo",
    ".whl", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".wav", ".sqlite",
    ".db", ".bin", ".iso", ".dmg", ".psd",
}
MAX_FILE_SIZE = 1_000_000
CONTEXT_LINES = 3
IGNORE_FILE = ".localauditignore"


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    notices: list[str] = field(default_factory=list)


# ---- ignore handling ----------------------------------------------------------------------------

def load_ignore_patterns(root: Path) -> list[str]:
    path = root / IGNORE_FILE
    if not path.is_file():
        return []
    patterns = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def is_ignored(rel_path: str, patterns: list[str], is_dir: bool = False) -> bool:
    name = rel_path.rsplit("/", 1)[-1]
    for pat in patterns:
        dir_only = pat.endswith("/")
        p = pat.rstrip("/").lstrip("/")
        if dir_only and not is_dir:
            # a file is ignored if any parent directory matches
            if any(fnmatch.fnmatch(part, p) for part in rel_path.split("/")[:-1]) or rel_path.startswith(p + "/"):
                return True
            continue
        if fnmatch.fnmatch(rel_path, p) or fnmatch.fnmatch(name, p) or rel_path.startswith(p + "/"):
            return True
    return False


# ---- file scanning ------------------------------------------------------------------------------

def make_snippet(lines: list[str], line_no: int) -> tuple[str, int]:
    start = max(1, line_no - CONTEXT_LINES)
    end = min(len(lines), line_no + CONTEXT_LINES)
    return "\n".join(lines[start - 1:end]), start


def read_text(path: Path) -> Optional[str]:
    """Return file text, or None for binary / oversized / unreadable files."""
    if path.suffix.lower() in BINARY_EXTS:
        return None
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def scan_text(text: str, rel_path: str) -> list[Finding]:
    lines = text.splitlines()
    hits = secrets.scan_lines(lines)
    # Everything below works on redacted lines so no raw secret reaches a snippet or match.
    redacted = secrets.redact_lines(lines, hits)
    findings: list[Finding] = []

    for hit in hits:
        snippet, start = make_snippet(redacted, hit.line)
        p = hit.pattern
        findings.append(Finding(
            rule_id=p.id, title=p.title, severity=p.severity, category="secrets", file=rel_path,
            line=hit.line, snippet=snippet, snippet_start=start, match=hit.masked,
            description=p.description, cwe=p.cwe,
        ))

    language = LANGUAGE_BY_EXT.get(Path(rel_path).suffix.lower())
    active_rules = rules_for(language)
    for idx, line in enumerate(redacted, start=1):
        for rule in active_rules:
            m = rule.search(line)
            if not m:
                continue
            snippet, start = make_snippet(redacted, idx)
            findings.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity, category=rule.category,
                file=rel_path, line=idx, snippet=snippet, snippet_start=start, match=m.group(0).strip(),
                description=rule.description, cwe=rule.cwe,
            ))
    return findings


# ---- dependency checks --------------------------------------------------------------------------

_REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def _line_of(lines: list[str], needle: str) -> int:
    low = needle.lower()
    for i, line in enumerate(lines, start=1):
        if low in line.lower():
            return i
    return 1


def check_requirements(text: str, rel_path: str) -> list[Finding]:
    lines = text.splitlines()
    findings = []
    for idx, raw in enumerate(lines, start=1):
        line = raw.split(" #", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith(("#", "-")) or "://" in line or line.startswith((".", "/")):
            continue
        m = _REQ_NAME.match(line)
        if not m:
            continue
        name, spec = m.group(1), m.group(3).strip()
        pinned = spec.startswith("===") or (spec.startswith("==") and "*" not in spec and "," not in spec)
        if pinned:
            continue
        snippet, start = make_snippet(lines, idx)
        findings.append(Finding(
            rule_id="dep-unpinned-python", title=f"Unpinned Python dependency: {name}", severity="low",
            category="dependencies", file=rel_path, line=idx, snippet=snippet, snippet_start=start, match=line,
            description="The dependency is not pinned to an exact version (==), so builds are not reproducible "
                        "and a compromised or breaking release can be pulled in silently.",
            cwe="CWE-1357",
        ))
    return findings


def check_package_json(text: str, rel_path: str) -> list[Finding]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    lines = text.splitlines()
    findings = []
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, version in deps.items():
            v = str(version).strip()
            if v in ("*", "", "latest", "x") or v.startswith((">", "x")):
                idx = _line_of(lines, f'"{name}"')
                snippet, start = make_snippet(lines, idx)
                findings.append(Finding(
                    rule_id="dep-unbounded-npm", title=f"Unbounded npm dependency version: {name}", severity="low",
                    category="dependencies", file=rel_path, line=idx, snippet=snippet, snippet_start=start,
                    match=f'"{name}": "{v}"',
                    description="The dependency accepts any future version, so a malicious or breaking release "
                                "will be installed automatically.",
                    cwe="CWE-1357",
                ))
    return findings


def run_pip_audit(req_path: Path, rel_path: str, text: str, notices: list[str]) -> list[Finding]:
    exe = shutil.which("pip-audit")
    if not exe:
        msg = "pip-audit not installed; skipping known-vulnerability check (pip install pip-audit to enable)."
        if msg not in notices:
            notices.append(msg)
        return []
    try:
        proc = subprocess.run(
            [exe, "-r", str(req_path), "-f", "json", "--progress-spinner", "off"],
            capture_output=True, text=True, timeout=600,
        )
        data = json.loads(proc.stdout or "null")
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        notices.append(f"pip-audit failed on {rel_path} ({exc.__class__.__name__}); skipping.")
        return []
    deps = data.get("dependencies", []) if isinstance(data, dict) else (data or [])
    if not deps and proc.returncode not in (0, 1):
        notices.append(f"pip-audit could not audit {rel_path}: {proc.stderr.strip().splitlines()[-1:] or ['unknown error']}")
        return []
    lines = text.splitlines()
    findings = []
    for dep in deps:
        for vuln in dep.get("vulns", []) or []:
            name, version, vid = dep.get("name", "?"), dep.get("version", "?"), vuln.get("id", "?")
            fixes = ", ".join(vuln.get("fix_versions") or []) or "none listed"
            idx = _line_of(lines, name)
            snippet, start = make_snippet(lines, idx)
            desc = (vuln.get("description") or "").strip().replace("\n", " ")
            findings.append(Finding(
                rule_id="dep-pip-audit", title=f"Vulnerable dependency: {name} {version} ({vid})", severity="high",
                category="dependencies", file=rel_path, line=idx, snippet=snippet, snippet_start=start,
                match=f"{name}=={version}",
                description=(desc[:400] + ("..." if len(desc) > 400 else "")) + f" Fixed in: {fixes}.",
                cwe="CWE-1395",
            ))
    return findings


# ---- walker -------------------------------------------------------------------------------------

def scan(target: str | os.PathLike) -> ScanResult:
    root = Path(target).resolve()
    result = ScanResult(root=str(root))
    if root.is_file():
        files = [(root, root.name)]
        patterns: list[str] = []
    else:
        patterns = load_ignore_patterns(root)
        files = []
        for dirpath, dirnames, filenames in os.walk(root):
            base = Path(dirpath)
            rel_dir = base.relative_to(root).as_posix()
            rel_dir = "" if rel_dir == "." else rel_dir + "/"
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in SKIP_DIRS and not is_ignored(rel_dir + d, patterns, is_dir=True)
            )
            for fn in sorted(filenames):
                rel = rel_dir + fn
                if not is_ignored(rel, patterns):
                    files.append((base / fn, rel))

    for path, rel in files:
        text = read_text(path)
        if text is None:
            result.files_skipped += 1
            continue
        result.files_scanned += 1
        result.findings.extend(scan_text(text, rel))
        name = path.name.lower()
        is_req = name.startswith("requirements") and name.endswith(".txt")
        if is_req or name == "package.json":
            lines = text.splitlines()
            safe_text = "\n".join(secrets.redact_lines(lines, secrets.scan_lines(lines)))
            if is_req:
                result.findings.extend(check_requirements(safe_text, rel))
                if name == "requirements.txt":
                    result.findings.extend(run_pip_audit(path, rel, safe_text, result.notices))
            else:
                result.findings.extend(check_package_json(safe_text, rel))

    result.findings = sort_findings(result.findings)
    return result
