import json

import pytest
import requests

from localaudit import llm, report
from localaudit.models import Finding

GOOD = {
    "explanation": "eval runs arbitrary code.",
    "risk_in_context": "User input reaches eval directly.",
    "likely_false_positive": False,
    "confidence": "high",
    "suggested_fix": "Use ast.literal_eval.",
    "fixed_code_example": "value = ast.literal_eval(expr)",
}


class FakeResponse:
    def __init__(self, payload=None, status=200):
        self.payload = payload
        self.status_code = status

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}")


class FakeSession:
    """Returns queued responses (or raises queued exceptions) and records requests."""

    def __init__(self, posts=(), get=None):
        self.posts = list(posts)
        self.get_response = get
        self.requests = []

    def post(self, url, json=None, timeout=None):
        self.requests.append({"url": url, "json": json, "timeout": timeout})
        item = self.posts.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def get(self, url, timeout=None):
        if isinstance(self.get_response, Exception):
            raise self.get_response
        return self.get_response


def chat(content):
    return FakeResponse({"message": {"role": "assistant", "content": content}})


def make_finding(**kw):
    base = dict(rule_id="py-eval-exec", title="Use of eval/exec", severity="high", category="injection",
                file="app.py", line=5, snippet="a\nb\nc\nx = eval(expr)\nd\ne\nf", snippet_start=2,
                match="eval(", description="eval is dangerous", cwe="CWE-95")
    base.update(kw)
    return Finding(**base)


def test_valid_response_parsed_and_request_shape(tmp_path):
    session = FakeSession([chat(json.dumps(GOOD))])
    t = llm.Triager("qwen2.5-coder:7b", session=session, cache_dir=tmp_path)
    result, cached = t.triage(make_finding())
    assert result.available and not cached
    assert result.suggested_fix == "Use ast.literal_eval." and result.confidence == "high"
    req = session.requests[0]
    assert req["url"] == "http://localhost:11434/api/chat"
    assert req["timeout"] == 120
    body = req["json"]
    assert body["stream"] is False
    assert body["format"] == llm.TRIAGE_SCHEMA
    assert body["options"] == {"temperature": 0, "num_ctx": 4096}
    assert "x = eval(expr)" in body["messages"][1]["content"]
    assert "app.py" in body["messages"][1]["content"]


def test_invalid_json_retried_once_then_succeeds(tmp_path):
    session = FakeSession([chat("not json {"), chat(json.dumps(GOOD))])
    result, _ = llm.Triager("m", session=session, cache_dir=tmp_path).triage(make_finding())
    assert result.available
    assert len(session.requests) == 2


def test_invalid_json_twice_falls_back(tmp_path):
    session = FakeSession([chat("nope"), chat(json.dumps({"explanation": "missing keys"}))])
    result, _ = llm.Triager("m", session=session, cache_dir=tmp_path).triage(make_finding())
    assert not result.available
    assert result.note.startswith("LLM triage unavailable")
    assert len(session.requests) == 2


def test_http_error_and_timeout_fall_back(tmp_path):
    session = FakeSession([FakeResponse({"error": "boom"}, status=500), requests.Timeout()])
    t = llm.Triager("m", session=session, cache_dir=tmp_path)
    r1, _ = t.triage(make_finding())
    r2, _ = t.triage(make_finding(line=6))
    assert not r1.available and "unavailable" in r1.note
    assert not r2.available and "timed out" in r2.note


def test_cache_hit_skips_http(tmp_path):
    session = FakeSession([chat(json.dumps(GOOD))])
    llm.Triager("m", session=session, cache_dir=tmp_path).triage(make_finding())
    assert list(tmp_path.glob("*.json"))
    empty = FakeSession([])
    result, cached = llm.Triager("m", session=empty, cache_dir=tmp_path).triage(make_finding())
    assert cached and result.available and empty.requests == []
    # different model -> different key -> cache miss
    other = FakeSession([chat(json.dumps(GOOD))])
    _, cached = llm.Triager("other-model", session=other, cache_dir=tmp_path).triage(make_finding())
    assert not cached and len(other.requests) == 1


def test_ollama_down():
    ok, msg = llm.check_ollama("qwen2.5-coder:7b", session=FakeSession(get=requests.ConnectionError()))
    assert not ok and "ollama pull qwen2.5-coder:7b" in msg


def test_model_not_pulled():
    tags = FakeResponse({"models": [{"name": "llama3:8b", "model": "llama3:8b"}]})
    ok, msg = llm.check_ollama("qwen2.5-coder:7b", session=FakeSession(get=tags))
    assert not ok and "ollama pull qwen2.5-coder:7b" in msg


def test_model_available():
    tags = FakeResponse({"models": [{"name": "qwen2.5-coder:7b"}]})
    assert llm.check_ollama("qwen2.5-coder:7b", session=FakeSession(get=tags))[0]
    tags = FakeResponse({"models": [{"name": "mistral:latest"}]})
    assert llm.check_ollama("mistral", session=FakeSession(get=tags))[0]


def test_triage_findings_cap_order_and_abort(tmp_path):
    findings = [make_finding(severity=sev, line=n, snippet=f"x = eval(e{n})", snippet_start=n)
                for n, sev in enumerate(["low", "critical", "high", "medium"], start=1)]
    session = FakeSession([chat(json.dumps(GOOD)), requests.ConnectionError()])
    seen = []
    stats = llm.triage_findings(findings, llm.Triager("m", session=session, cache_dir=tmp_path), 3,
                                progress=lambda i, n, f: seen.append(f.severity))
    assert seen == ["critical", "high"]  # aborted after connection error, highest severity first
    assert stats == {"triaged": 1, "cached": 0, "failed": 2, "skipped": 1, "aborted": True}
    by_sev = {f.severity: f.triage for f in findings}
    assert by_sev["critical"].available
    assert "unreachable" in by_sev["high"].note and "unreachable" in by_sev["medium"].note
    assert "max-llm-findings" in by_sev["low"].note


def test_false_positive_kept_in_separate_section(tmp_path):
    fp = dict(GOOD, likely_false_positive=True, confidence="medium")
    session = FakeSession([chat(json.dumps(fp))])
    f = make_finding()
    llm.triage_findings([f], llm.Triager("m", session=session, cache_dir=tmp_path), 25)
    data = report.build_report_data([f], {})
    assert data["findings"] == [] and data["false_positives"] == [f]
    assert data["summary"]["likely_false_positives"] == 1
    assert data["summary"]["risk_score"] == 0


def test_prompt_contains_only_masked_secrets():
    from localaudit.scanner import scan_text
    findings = scan_text('DEBUG = True\napi_token = "Zq8mT3xV1nB7cK5pR2wY9hL4"\n', "settings.py")
    for f in findings:
        prompt = json.dumps(llm.build_messages(f))
        assert "Zq8mT3xV1nB7cK5pR2wY9hL4" not in prompt
        assert "Zq8m****" in prompt


@pytest.mark.parametrize("env,expected", [(None, "qwen2.5-coder:7b"), ("llama3.1:8b", "llama3.1:8b")])
def test_default_model_env(monkeypatch, env, expected):
    if env:
        monkeypatch.setenv("LOCALAUDIT_MODEL", env)
    else:
        monkeypatch.delenv("LOCALAUDIT_MODEL", raising=False)
    assert llm.default_model() == expected
