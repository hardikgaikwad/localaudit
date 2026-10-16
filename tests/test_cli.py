import json
import re
from pathlib import Path

import pytest

from localaudit import cli, llm
from test_scanner import EXAMPLE, RAW_SECRETS


def run(args):
    return cli.main(["scan", *args])


def test_no_llm_end_to_end_writes_all_reports(tmp_path, capsys):
    out = tmp_path / "out"
    assert run([str(EXAMPLE), "--no-llm", "--out", str(out)]) == 0
    files = {p.name for p in out.iterdir()}
    assert files == {"report.html", "report.json", "report.md"}

    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["meta"]["model"] is None
    assert data["summary"]["total"] == len(data["findings"]) > 30
    assert 0 <= data["summary"]["risk_score"] <= 100

    html = (out / "report.html").read_text(encoding="utf-8")
    assert "Risk score" in html and "@media print" in html
    # self-contained: no external stylesheets, scripts, images or fonts
    assert not re.search(r"<(script|img|link)[^>]+(src|href)=", html)
    assert "@import" not in html and "url(" not in html

    for name in files:
        text = (out / name).read_text(encoding="utf-8")
        for raw in RAW_SECRETS:
            assert raw not in text, (name, raw)
    for raw in RAW_SECRETS:
        assert raw not in capsys.readouterr().out


def test_formats_and_min_severity(tmp_path):
    out = tmp_path / "out"
    assert run([str(EXAMPLE), "--no-llm", "--out", str(out), "--format", "json", "--min-severity", "high"]) == 0
    assert [p.name for p in out.iterdir()] == ["report.json"]
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert {f["severity"] for f in data["findings"]} <= {"critical", "high"}


def test_fail_on(tmp_path):
    assert run([str(EXAMPLE), "--no-llm", "--out", str(tmp_path), "--fail-on", "critical"]) == 1
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "ok.py").write_text("print('hello')\n")
    assert run([str(clean), "--no-llm", "--out", str(tmp_path / "o2"), "--fail-on", "info"]) == 0


def test_ollama_down_falls_back_to_rules_only(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(llm, "check_ollama", lambda model: (False, f"Run: ollama pull {model}"))
    out = tmp_path / "out"
    assert run([str(EXAMPLE), "--out", str(out), "--model", "some-model:1b"]) == 0
    err = capsys.readouterr().err
    assert "ollama pull some-model:1b" in err
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["meta"]["model"] is None and data["summary"]["total"] > 30


def test_bad_arguments():
    with pytest.raises(SystemExit):
        run(["x", "--min-severity", "extreme"])
    with pytest.raises(SystemExit):
        run(["x", "--format", "pdf"])
    assert run([str(Path("definitely/not/here")), "--no-llm"]) == 2
