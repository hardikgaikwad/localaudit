"""Built-in secret detection: provider-specific regexes, generic assignments, and entropy.

Detected values are only ever exposed in masked form (first 4 characters + ****).
`redact_lines` must be applied to file contents before any snippet is built.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

MASK = "****"
ENTROPY_THRESHOLD = 3.5
ENTROPY_MIN_LENGTH = 16


def mask(value: str) -> str:
    return value[:4] + MASK


@dataclass(frozen=True)
class SecretPattern:
    id: str
    title: str
    severity: str
    regex: re.Pattern
    group: int = 0  # capture group holding the secret value
    cwe: str = "CWE-798"
    description: str = ""


SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        "secret-private-key", "Private key block", "critical",
        re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
        description="A private key is committed to the repository. Anyone with read access can impersonate its owner.",
    ),
    SecretPattern(
        "secret-aws-access-key", "AWS access key ID", "critical",
        re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), group=1,
        description="An AWS access key ID is hardcoded. It is usually paired with a secret key nearby and grants AWS API access.",
    ),
    SecretPattern(
        "secret-github-token", "GitHub token", "critical",
        re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b"), group=1,
        description="A GitHub personal access or app token is hardcoded and may grant repository or org access.",
    ),
    SecretPattern(
        "secret-slack-token", "Slack token", "high",
        re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b"), group=1,
        description="A Slack API token is hardcoded and may allow reading or posting messages in a workspace.",
    ),
    SecretPattern(
        "secret-stripe-live-key", "Stripe live secret key", "critical",
        re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b"), group=1,
        description="A Stripe live-mode secret key is hardcoded and allows real payment operations.",
    ),
    SecretPattern(
        "secret-google-api-key", "Google API key", "high",
        re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), group=1,
        description="A Google API key is hardcoded and may be abused for billable API calls.",
    ),
    SecretPattern(
        "secret-jwt", "JSON Web Token", "medium",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"), group=1,
        description="A JWT is hardcoded. If it is not expired it can be replayed to authenticate as its subject.",
    ),
    SecretPattern(
        "secret-django-secret-key", "Hardcoded Django SECRET_KEY", "high",
        re.compile(r"^\s*SECRET_KEY\s*=\s*[rbu]?(['\"])(?P<v>[^'\"]+)\1"), group=2,
        description="Django's SECRET_KEY is hardcoded. It signs sessions, password-reset tokens and CSRF tokens; "
                    "leaking it can allow session forgery.",
    ),
]

# `password = "..."`, `api_key: '...'`, `"token": "..."` etc.
GENERIC_ASSIGNMENT = re.compile(
    r"""(?ix)
    ["']?(?P<name>\b[A-Za-z0-9_]*?(?:password|passwd|pwd|secret|api_?key|token)[A-Za-z0-9_]*)\b["']?
    \s*(?::=|=|:)\s*[rbu]?
    (?P<q>["'])(?P<v>[^"'\n]*)(?P=q)
    """
)

# Broader names that only fire when the literal also looks random.
ENTROPY_ASSIGNMENT = re.compile(
    r"""(?ix)
    ["']?(?P<name>\b[A-Za-z0-9_]*?(?:key|secret|token|passw\w*|pwd|cred\w*|auth|private|signature|salt|dsn|conn\w*)[A-Za-z0-9_]*)\b["']?
    \s*(?::=|=|:)\s*[rbu]?
    (?P<q>["'])(?P<v>[^"'\n\s]{%d,})(?P=q)
    """ % ENTROPY_MIN_LENGTH
)

GENERIC_INFO = SecretPattern(
    "secret-generic-assignment", "Hardcoded credential", "high", GENERIC_ASSIGNMENT,
    description="A password, secret, API key or token is assigned a string literal in source code.",
)
ENTROPY_INFO = SecretPattern(
    "secret-high-entropy-string", "High-entropy string in credential-like variable", "medium", ENTROPY_ASSIGNMENT,
    description="A random-looking string literal is assigned to a variable whose name suggests a credential.",
)

PLACEHOLDER_RE = re.compile(
    r"""(?ix)
    changeme | change[_-]me | your[_-]?\w*[_-]?here | ^your[_-] | example | placeholder | redacted | dummy
    | x{3,} | \*{3,} | ^<.*>$ | \$\{.*\} | \{\{.*\}\} | %\(.*\)s | ^\$[A-Z_]+$ | ^(none|null|nil|undefined|true|false|todo)$
    """
)
ENV_LOOKUP_RE = re.compile(r"os\.environ|os\.getenv|getenv\(|process\.env|config\(|settings\.|ENV\[")


def is_placeholder(value: str) -> bool:
    v = value.strip()
    if len(v) < 4:
        return True
    if len(set(v)) == 1:  # "aaaaaaaa", "00000000"
        return True
    return bool(PLACEHOLDER_RE.search(v))


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    n = len(value)
    return -sum((k / n) * math.log2(k / n) for k in counts.values())


@dataclass
class SecretHit:
    pattern: SecretPattern
    line: int  # 1-based
    value: str  # raw value; never output this directly

    @property
    def masked(self) -> str:
        if self.pattern.id == "secret-private-key":
            return self.value  # the BEGIN header itself is not secret; the body is redacted separately
        return mask(self.value)


def scan_lines(lines: list[str]) -> list[SecretHit]:
    hits: list[SecretHit] = []
    for idx, line in enumerate(lines, start=1):
        claimed: list[tuple[int, int]] = []  # value spans already reported on this line

        def overlaps(span: tuple[int, int]) -> bool:
            return any(span[0] < e and s < span[1] for s, e in claimed)

        for pat in SECRET_PATTERNS:
            for m in pat.regex.finditer(line):
                value = m.group(pat.group)
                if pat.id != "secret-private-key" and is_placeholder(value):
                    continue
                claimed.append(m.span(pat.group))
                hits.append(SecretHit(pat, idx, value))

        if ENV_LOOKUP_RE.search(line):  # value comes from env/config; only provider-specific keys count
            continue
        for info, check_entropy in ((GENERIC_INFO, False), (ENTROPY_INFO, True)):
            for m in info.regex.finditer(line):
                value, name = m.group("v"), m.group("name")
                span = m.span("v")
                if overlaps(span) or is_placeholder(value):
                    continue
                if value.lower() in name.lower():  # e.g. password_field = "password"
                    continue
                if check_entropy and shannon_entropy(value) < ENTROPY_THRESHOLD:
                    continue
                claimed.append(span)
                hits.append(SecretHit(info, idx, value))
    return hits


_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----")
_KEY_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----")


def redact_lines(lines: list[str], hits: list[SecretHit]) -> list[str]:
    """Return a copy of `lines` with every detected secret value masked and private-key bodies removed."""
    values = sorted({h.value for h in hits if h.pattern.id != "secret-private-key"}, key=len, reverse=True)
    out: list[str] = []
    in_key = False
    for line in lines:
        if in_key:
            if _KEY_END.search(line):
                in_key = False
                out.append(line)
            else:
                out.append(MASK if line.strip() else line)
            continue
        if _KEY_BEGIN.search(line):
            # Mask anything after the header on the same line (single-line / escaped "\n" keys).
            m = _KEY_BEGIN.search(line)
            rest = line[m.end():]
            end = _KEY_END.search(rest)
            if end:
                line = line[: m.end()] + MASK + rest[end.start():]
            else:
                line = line[: m.end()] + (MASK if rest.strip() else "")
                in_key = True
        for v in values:
            if v in line:
                line = line.replace(v, mask(v))
        out.append(line)
    return out
