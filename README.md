# LocalAudit

A command-line security audit tool for source code repositories that runs **100% locally**.

- **Deterministic rules find the issues**: built-in secret detection, about 25 code-pattern rules for Python/Django/Flask, JavaScript/Node and generic files, and dependency pinning checks.
- **A local LLM triages them** through [Ollama](https://ollama.com). For each finding it explains the issue in plain language, judges whether it is likely a false positive, and suggests a concrete fix.
- The LLM **never detects** vulnerabilities, and it never deletes a finding. Anything it judges a likely false positive goes into a separate section for you to review.
- The report is complete and useful without the LLM (`--no-llm`, or when Ollama isn't running).

Output: a self-contained `report.html` (no CDN or external requests, and it prints cleanly to PDF), plus `report.json` and `report.md`.

## 60-second quickstart

```bash
# 1. Get the model (one time, ~4.7 GB)
ollama pull qwen2.5-coder:7b

# 2. Install LocalAudit
pip install -e .            # add ".[dev]" for pytest

# 3. Scan the intentionally vulnerable demo app
localaudit scan examples/vulnerable_app
# then open localaudit-report/report.html
```

You can try it without Ollama: `localaudit scan examples/vulnerable_app --no-llm`.

> If `localaudit` is "not found" after installing, pip put the script in a user Scripts directory that isn't on your `PATH`. Run `python -m localaudit scan ...` instead, or add that directory to `PATH`.

## CLI

```
localaudit scan PATH [--model M] [--out DIR] [--no-llm] [--max-llm-findings N]
                     [--min-severity LEVEL] [--format html,json,md] [--fail-on LEVEL]
```

| Option | Default | Meaning |
|---|---|---|
| `PATH` | | File or directory to scan |
| `--model M` | `$LOCALAUDIT_MODEL` or `qwen2.5-coder:7b` | Ollama model used for triage |
| `--out DIR` | `./localaudit-report` | Where reports are written |
| `--no-llm` | off | Rules only, with no Ollama calls |
| `--max-llm-findings N` | `25` | Cap on findings sent to the LLM, highest severity first. The rest are reported untriaged |
| `--min-severity LEVEL` | `info` | Drop findings below `critical`/`high`/`medium`/`low`/`info` |
| `--format` | `html,json,md` | Comma-separated output formats |
| `--fail-on LEVEL` | unset | Exit code `1` if any finding is at or above `LEVEL` (for CI) |

Exit codes: `0` success, `1` `--fail-on` threshold hit, `2` bad arguments or missing path.

`--fail-on` counts **every** finding, including ones the LLM marked as likely false positives. A small model's judgement shouldn't be able to turn a CI gate green on its own. Suppress real false positives with `.localauditignore` instead.

### CI example

```bash
localaudit scan . --no-llm --format json --fail-on high
```

## What it checks

**Secrets** (`localaudit/secrets.py`, no external tools): AWS access key IDs, private key blocks, GitHub tokens, Slack tokens, Stripe live keys, Google API keys, JWTs, a hardcoded Django `SECRET_KEY`, generic `password/secret/api_key/token = "<literal>"` assignments, and high-entropy literals assigned to credential-like names (Shannon entropy >= 3.5, length >= 16).
Obvious placeholders are ignored (`changeme`, `your_key_here`, `example`, `xxx`, `<...>`, `${...}`, `{{...}}`), and so are env lookups (`os.environ`, `getenv`, `process.env`).

**Secrets are always masked**: only the first 4 characters followed by `****` ever appear. Detected values, and the bodies of private keys, are redacted from the file text *before* any snippet is built. That means they're also masked when they show up as context lines around other findings, in the console, and in the LLM prompt.

**Code patterns** (`localaudit/rules.py`):

- **Python/Django/Flask:** `DEBUG = True`, wildcard `ALLOWED_HOSTS`, `eval`/`exec`, `pickle.loads`, `yaml.load` without `SafeLoader`, `subprocess(..., shell=True)`, `os.system`, string-formatted SQL passed to `execute()`/`raw()`, `verify=False`, MD5/SHA1 for passwords, `CORS_ALLOW_ALL_ORIGINS = True`, `@csrf_exempt`, `mark_safe`, `app.run(debug=True)`
- **JS/Node:** `eval(`, `exec` with template strings or concatenation, `innerHTML =`, `dangerouslySetInnerHTML`, `rejectUnauthorized: false`, `Math.random` for tokens, wildcard CORS / bare `cors()`
- **Generic:** hardcoded private IPs and internal URLs, TODO/FIXME comments that mention security or auth, `chmod 777`

**Dependencies:** unpinned entries in `requirements*.txt` and `*`/`latest`/`>=` versions in `package.json`. If [`pip-audit`](https://pypi.org/project/pip-audit/) is installed, it runs on `requirements.txt` and its known-vulnerability results are imported as findings. If it isn't installed, you get a one-line notice and the scan continues. Note that pip-audit queries a vulnerability database online using package names and versions; your source code is never sent.

**Skipped automatically:** `.git`, `node_modules`, `venv`/`.venv`, `__pycache__`, `dist`, `build`, binary files, and files over 1 MB. To skip more, put a `.localauditignore` in the scan root with one glob per line:

```
# .localauditignore
vendor/
tests/fixtures/*
*.min.js
```

## LLM triage

For each finding, highest severity first up to `--max-llm-findings`, LocalAudit sends the rule description, file path and **masked** snippet (+/-3 lines) to `http://localhost:11434/api/chat`. The request uses `stream: false`, `temperature: 0` and `num_ctx: 4096`, with a JSON schema in Ollama's `format` parameter, so the model must return:

```json
{"explanation": "...", "risk_in_context": "...", "likely_false_positive": false,
 "confidence": "low|medium|high", "suggested_fix": "...", "fixed_code_example": "..."}
```

- The request timeout is 120 s. If the model returns invalid JSON, LocalAudit retries once, then marks the finding *"LLM triage unavailable"*.
- Results are cached in `.localaudit_cache/`, keyed by a hash of model + rule + snippet, so reruns are fast.
- Before triage starts, LocalAudit checks `GET /api/tags`. If Ollama isn't running or the model isn't pulled, it prints the exact fix (for example `ollama pull qwen2.5-coder:7b`) and continues in rules-only mode.

Speed depends on your hardware. On a GPU that fits the whole model, expect a few seconds per finding. A 7B model split between CPU and GPU can take close to a minute per finding. Use `--max-llm-findings`, `--min-severity high`, or a smaller model (`--model qwen2.5-coder:3b`) to trade depth for speed.

## Why a local open-weight model

- **Your source code never leaves the machine.** Audit code is often the most sensitive code you have, and it may contain live secrets. Everything, including the model, runs on localhost. Even so, LocalAudit masks secrets before the model sees them.
- **No per-scan API cost.** Rerun it on every commit, on every branch, as often as you like.
- **The model is swappable.** Use `--model` or `LOCALAUDIT_MODEL` to pick any model you've pulled into Ollama. Choose a bigger model for better judgement or a smaller one for speed, and upgrade whenever a better open-weight model comes out.

## Adding a rule

Append a `Rule` to `RULES` in `localaudit/rules.py`:

```python
Rule("py-tempfile-mktemp", "Insecure tempfile.mktemp", "medium", "filesystem", "CWE-377",
     "tempfile.mktemp() is race-prone; use NamedTemporaryFile or mkstemp.",
     r"\btempfile\.mktemp\s*\(", PY),
```

The fields are: id, title, severity, category, CWE, description, regex, and languages (`PY`, `JS`, or `None` for all files). Rules match one line at a time, and comment lines are skipped unless you pass `skip_comments=False`. Then add a known-bad line and a safe line to `CASES` in `tests/test_rules.py`. The test suite fails if a rule has no case.

New secret formats go in `SECRET_PATTERNS` in `localaudit/secrets.py`. Masking applies to them automatically.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The tests use a mocked HTTP session for the LLM, so they don't need Ollama.

## Limitations

- **Detection is regex-based and line-oriented.** It doesn't do data-flow or taint analysis, so it misses multi-line constructs (for example a `subprocess.run(` call whose `shell=True` is on another line) and anything not covered by a rule. It also flags safe code that happens to look dangerous. Treat the output as a review checklist, not a verdict.
- **Small local models can misjudge.** They can mark real issues as false positives or the reverse, and suggested fixes may be incomplete or wrong. That's why likely false positives stay in the report and still count toward `--fail-on`.
- **Masking only covers what is detected.** A secret in a format no rule recognises can still appear in a snippet next to some other finding.
- Only Python, JavaScript/TypeScript and a few generic patterns are covered.
- **This is not a replacement for a professional penetration test** or a full SAST/SCA product.

## Demo app

`examples/vulnerable_app/` is **intentionally insecure**, and all of its credentials are fake. It exists only to show the rules firing. Don't deploy or copy it.
