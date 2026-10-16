"""Local LLM triage through the Ollama HTTP API.

The model never detects issues. It only explains an existing rule finding, judges whether it is likely a
false positive, and suggests a fix. Only masked snippets are ever sent, and only to the local Ollama server.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Callable, Optional

import requests

from .models import Finding, Triage, sort_findings

OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5-coder:7b"
REQUEST_TIMEOUT = 120
CACHE_DIR = ".localaudit_cache"
UNAVAILABLE = "LLM triage unavailable"

TRIAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "explanation": {"type": "string"},
        "risk_in_context": {"type": "string"},
        "likely_false_positive": {"type": "boolean"},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "suggested_fix": {"type": "string"},
        "fixed_code_example": {"type": "string"},
    },
    "required": ["explanation", "risk_in_context", "likely_false_positive", "confidence",
                 "suggested_fix", "fixed_code_example"],
}

SYSTEM_PROMPT = """You are a senior application security reviewer helping triage the output of a static analysis tool.
A deterministic rule has already flagged the code below. Do NOT look for other vulnerabilities; only assess this one finding.
Secret values in the code have been deliberately masked as "abcd****" by the tool. Masking is not a problem to report.
Respond with JSON only, matching the provided schema:
- explanation: 1-3 sentences, plain language, what the issue is and why it matters.
- risk_in_context: 1-2 sentences on how risky it is given the surrounding code (e.g. test code, constant input, dead code).
- likely_false_positive: true only if the surrounding code clearly shows the flagged pattern is not exploitable or not a real secret.
- confidence: low, medium or high confidence in your false-positive judgement.
- suggested_fix: a concrete, specific fix in 1-3 sentences.
- fixed_code_example: a short corrected version of the flagged line(s), or "" if not applicable."""


def default_model() -> str:
    return os.environ.get("LOCALAUDIT_MODEL") or DEFAULT_MODEL


class OllamaUnavailable(Exception):
    """Ollama cannot be reached; stop triaging."""


class InvalidResponse(Exception):
    """Model returned something that is not valid triage JSON."""


def _model_names(tags: dict) -> set[str]:
    names = set()
    for m in tags.get("models", []) or []:
        for key in ("name", "model"):
            if m.get(key):
                names.add(m[key])
    return names


def check_ollama(model: str, base_url: str = OLLAMA_URL, session=None) -> tuple[bool, str]:
    """Return (ok, message). Message tells the user exactly how to fix a problem."""
    http = session or requests
    try:
        resp = http.get(f"{base_url}/api/tags", timeout=5)
        resp.raise_for_status()
        tags = resp.json()
    except (requests.RequestException, ValueError):
        return False, (f"Ollama is not reachable at {base_url}. Start it with `ollama serve` "
                       f"(and `ollama pull {model}` if needed). Continuing with --no-llm.")
    names = _model_names(tags)
    wanted = {model} if ":" in model else {model, f"{model}:latest"}
    if not names & wanted:
        return False, f"Model '{model}' is not pulled. Run: ollama pull {model}   Continuing with --no-llm."
    return True, f"Ollama OK, model {model}"


def build_messages(f: Finding) -> list[dict]:
    numbered = "\n".join(
        f"{f.snippet_start + i:>5}{' >' if f.snippet_start + i == f.line else '  '} {text}"
        for i, text in enumerate(f.snippet.split("\n"))
    )
    user = (
        f"Rule: {f.rule_id} - {f.title}\n"
        f"Severity: {f.severity}\n"
        f"CWE: {f.cwe or 'n/a'}\n"
        f"Rule description: {f.description}\n"
        f"File: {f.file}\n"
        f"Flagged line: {f.line} (marked with >)\n"
        f"Matched text: {f.match}\n\n"
        f"Code:\n{numbered}\n"
    )
    return [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}]


def parse_triage(content: str) -> Triage:
    try:
        data = json.loads(content)
    except (TypeError, ValueError) as exc:
        raise InvalidResponse(str(exc)) from exc
    if not isinstance(data, dict):
        raise InvalidResponse("not an object")
    try:
        fp = data["likely_false_positive"]
        if isinstance(fp, str):
            fp = fp.strip().lower() == "true"
        confidence = str(data["confidence"]).strip().lower()
        if confidence not in ("low", "medium", "high"):
            raise InvalidResponse(f"bad confidence {confidence!r}")
        return Triage(
            available=True,
            explanation=str(data["explanation"]).strip(),
            risk_in_context=str(data["risk_in_context"]).strip(),
            likely_false_positive=bool(fp),
            confidence=confidence,
            suggested_fix=str(data["suggested_fix"]).strip(),
            fixed_code_example=str(data.get("fixed_code_example") or "").strip(),
        )
    except KeyError as exc:
        raise InvalidResponse(f"missing key {exc}") from exc


def cache_key(model: str, f: Finding) -> str:
    return hashlib.sha256(f"{model}\x00{f.rule_id}\x00{f.snippet}".encode()).hexdigest()


class Triager:
    def __init__(self, model: str, base_url: str = OLLAMA_URL, cache_dir: Optional[str | Path] = CACHE_DIR,
                 session=None, timeout: int = REQUEST_TIMEOUT):
        self.model = model
        self.base_url = base_url
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.http = session or requests.Session()
        self.timeout = timeout

    # -- cache --
    def _cache_get(self, key: str) -> Optional[Triage]:
        if not self.cache_dir:
            return None
        path = self.cache_dir / f"{key}.json"
        try:
            return Triage(**json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError):
            return None

    def _cache_put(self, key: str, triage: Triage) -> None:
        if not self.cache_dir:
            return
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            (self.cache_dir / f"{key}.json").write_text(json.dumps(triage.__dict__), encoding="utf-8")
        except OSError:
            pass

    # -- HTTP --
    def _chat(self, messages: list[dict]) -> str:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "format": TRIAGE_SCHEMA,
            "options": {"temperature": 0, "num_ctx": 4096},
        }
        try:
            resp = self.http.post(f"{self.base_url}/api/chat", json=payload, timeout=self.timeout)
        except requests.ConnectionError as exc:
            raise OllamaUnavailable(str(exc)) from exc
        resp.raise_for_status()
        try:
            return resp.json()["message"]["content"]
        except (ValueError, KeyError, TypeError) as exc:
            raise InvalidResponse("unexpected response shape") from exc

    def triage(self, f: Finding) -> tuple[Triage, bool]:
        """Return (triage, from_cache). Raises OllamaUnavailable if the server went away."""
        key = cache_key(self.model, f)
        cached = self._cache_get(key)
        if cached and cached.available:
            return cached, True
        messages = build_messages(f)
        for _attempt in range(2):  # one retry on invalid JSON
            try:
                result = parse_triage(self._chat(messages))
            except InvalidResponse:
                continue
            except requests.Timeout:
                return Triage(note=f"{UNAVAILABLE} (request timed out after {self.timeout}s)"), False
            except requests.RequestException as exc:
                return Triage(note=f"{UNAVAILABLE} ({exc.__class__.__name__})"), False
            self._cache_put(key, result)
            return result, False
        return Triage(note=f"{UNAVAILABLE} (model returned invalid JSON twice)"), False


def triage_findings(findings: list[Finding], triager: Triager, max_findings: int,
                    progress: Optional[Callable[[int, int, Finding], None]] = None) -> dict:
    """Triage findings highest-severity first, in place. Returns simple stats."""
    ordered = sort_findings(findings)
    selected, rest = ordered[:max_findings], ordered[max_findings:]
    stats = {"triaged": 0, "cached": 0, "failed": 0, "skipped": len(rest), "aborted": False}
    for f in rest:
        f.triage = Triage(note=f"Not triaged (beyond --max-llm-findings {max_findings})")
    for i, f in enumerate(selected, start=1):
        if stats["aborted"]:
            f.triage = Triage(note=f"{UNAVAILABLE} (Ollama became unreachable)")
            stats["failed"] += 1
            continue
        if progress:
            progress(i, len(selected), f)
        try:
            result, cached = triager.triage(f)
        except OllamaUnavailable:
            stats["aborted"] = True
            f.triage = Triage(note=f"{UNAVAILABLE} (Ollama became unreachable)")
            stats["failed"] += 1
            continue
        f.triage = result
        if result.available:
            stats["triaged"] += 1
            stats["cached"] += int(cached)
        else:
            stats["failed"] += 1
    return stats
