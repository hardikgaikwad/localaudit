from pathlib import Path

from localaudit import scanner
from localaudit.rules import RULES

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_app"

# Raw fake values that appear in the example app and must never be output.
RAW_SECRETS = [
    "AKIAZ7FAKEQ3LOCALAUD", "q8Rk2vN0fLp5Zx7Tb3Wm9Yc1Hd6Gs4Je0Ua2Oi8E", "Sup3rS3cretDbPass!",
    "ghp_Fak3T0kenF0rLocalAuditDem0nstrati0n1", "sk_live_FAKEfakeFAKEfake0123456789abcd",
    "AIzaSyFAKE_fake-FAKE_fake-0123456789abc", "NOTAREALKEY", "Zq8mT3xV1nB7cK5pR2wY9hL4",
    "django-insecure-9f#k2!qz7w@v1m$x8r4t^p6s0n3b5c&h",
]


def test_example_app_expected_findings():
    result = scanner.scan(EXAMPLE)
    found = {(f.rule_id, f.file) for f in result.findings}
    expected = {
        ("py-django-debug", "shop/settings.py"),
        ("py-django-allowed-hosts-wildcard", "shop/settings.py"),
        ("secret-django-secret-key", "shop/settings.py"),
        ("py-django-cors-allow-all", "shop/settings.py"),
        ("secret-aws-access-key", "shop/settings.py"),
        ("secret-generic-assignment", "shop/settings.py"),
        ("gen-internal-address", "shop/settings.py"),
        ("py-sql-string-format", "shop/views.py"),
        ("py-django-csrf-exempt", "shop/views.py"),
        ("py-pickle-loads", "shop/views.py"),
        ("py-yaml-load", "shop/views.py"),
        ("py-eval-exec", "shop/views.py"),
        ("py-os-system", "shop/views.py"),
        ("py-subprocess-shell", "shop/views.py"),
        ("py-django-mark-safe", "shop/views.py"),
        ("py-requests-verify-false", "shop/views.py"),
        ("py-weak-password-hash", "shop/views.py"),
        ("gen-security-todo", "shop/views.py"),
        ("secret-github-token", "shop/integrations.py"),
        ("secret-slack-token", "shop/integrations.py"),
        ("secret-stripe-live-key", "shop/integrations.py"),
        ("secret-google-api-key", "shop/integrations.py"),
        ("secret-jwt", "shop/integrations.py"),
        ("secret-high-entropy-string", "shop/integrations.py"),
        ("secret-private-key", "shop/integrations.py"),
        ("py-flask-debug", "shop/integrations.py"),
        ("js-cors-wildcard", "frontend/server.js"),
        ("js-child-process-exec", "frontend/server.js"),
        ("js-eval", "frontend/server.js"),
        ("js-math-random-token", "frontend/server.js"),
        ("js-tls-reject-unauthorized", "frontend/server.js"),
        ("js-dangerously-set-inner-html", "frontend/widget.jsx"),
        ("js-innerhtml", "frontend/widget.jsx"),
        ("gen-chmod-777", "deploy.sh"),
        ("dep-unpinned-python", "requirements.txt"),
        ("dep-unbounded-npm", "frontend/package.json"),
    }
    missing = expected - found
    assert not missing, f"missing findings: {sorted(missing)}"
    # every code rule fires somewhere in the demo app
    assert {r.id for r in RULES} <= {f.rule_id for f in result.findings}
    # placeholder and env lookup in settings.py are not flagged
    settings_lines = {f.line for f in result.findings if f.file == "shop/settings.py" and f.category == "secrets"}
    text = (EXAMPLE / "shop" / "settings.py").read_text().splitlines()
    assert not any("your_key_here" in text[n - 1] or "os.environ" in text[n - 1] for n in settings_lines)


def test_example_app_never_exposes_raw_secrets():
    result = scanner.scan(EXAMPLE)
    for f in result.findings:
        for raw in RAW_SECRETS:
            assert raw not in f.snippet, (f.rule_id, raw)
            assert raw not in f.match, (f.rule_id, raw)


def test_finding_fields_and_snippet_context():
    result = scanner.scan(EXAMPLE)
    f = next(f for f in result.findings if f.rule_id == "py-eval-exec")
    assert f.id.startswith("LA-") and f.severity == "high" and f.cwe == "CWE-95"
    lines = f.snippet.split("\n")
    assert len(lines) == 7  # 3 before + line + 3 after
    assert f.snippet_start == f.line - 3
    assert "eval(" in lines[3]


def test_findings_sorted_by_severity():
    result = scanner.scan(EXAMPLE)
    from localaudit.models import SEVERITY_RANK
    ranks = [SEVERITY_RANK[f.severity] for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_skips_dirs_binaries_large_files_and_ignore_file(tmp_path):
    bad = "result = eval(x)\n"
    _write(tmp_path / "app.py", bad)
    for d in (".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"):
        _write(tmp_path / d / "x.py", bad)
    (tmp_path / "blob.py").write_bytes(b"eval(x)\x00\x01\x02")
    _write(tmp_path / "big.py", bad + "#" * (scanner.MAX_FILE_SIZE + 10))
    _write(tmp_path / "vendor" / "lib.py", bad)
    _write(tmp_path / "generated_api.py", bad)
    _write(tmp_path / ".localauditignore", "# comment\nvendor/\ngenerated_*.py\n")

    result = scanner.scan(tmp_path)
    assert {f.file for f in result.findings} == {"app.py"}
    assert result.files_skipped == 2  # binary + oversized


def test_requirements_pinning():
    text = "Django==4.2.0\nrequests\nPyYAML>=5.1\n# comment\n-r base.txt\nflask==2.*\nidna===3.4\n"
    names = [f.match for f in scanner.check_requirements(text, "requirements.txt")]
    assert names == ["requests", "PyYAML>=5.1", "flask==2.*"]


def test_package_json_unbounded():
    text = '{"dependencies": {"a": "^1.0.0", "b": "*", "c": "latest"}, "devDependencies": {"d": "1.2.3"}}'
    findings = scanner.check_package_json(text, "package.json")
    assert sorted(f.match for f in findings) == ['"b": "*"', '"c": "latest"']


def test_missing_pip_audit_is_a_notice_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda name: None)
    _write(tmp_path / "requirements.txt", "requests\n")
    result = scanner.scan(tmp_path)
    assert any("pip-audit not installed" in n for n in result.notices)
    assert [f.rule_id for f in result.findings] == ["dep-unpinned-python"]


def test_pip_audit_results_imported(tmp_path, monkeypatch):
    import json
    import subprocess

    monkeypatch.setattr(scanner.shutil, "which", lambda name: "pip-audit")
    payload = {"dependencies": [{"name": "django", "version": "4.2.0",
                                 "vulns": [{"id": "PYSEC-2023-1", "fix_versions": ["4.2.1"], "description": "Bad."}]}]}
    monkeypatch.setattr(scanner.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 1, json.dumps(payload), ""))
    _write(tmp_path / "requirements.txt", "Django==4.2.0\n")
    result = scanner.scan(tmp_path)
    f = next(f for f in result.findings if f.rule_id == "dep-pip-audit")
    assert "PYSEC-2023-1" in f.title and f.line == 1 and "4.2.1" in f.description


def test_scan_single_file(tmp_path):
    _write(tmp_path / "one.js", "el.innerHTML = x;\n")
    result = scanner.scan(tmp_path / "one.js")
    assert [f.rule_id for f in result.findings] == ["js-innerhtml"]
