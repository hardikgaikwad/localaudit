import pytest

from localaudit import secrets
from localaudit.scanner import scan_text

# All values are fake and only match the formats.
FAKES = {
    "secret-aws-access-key": ('key_id = "AKIAZ7FAKEQ3LOCALAUD"', "AKIAZ7FAKEQ3LOCALAUD"),
    "secret-github-token": ('t = "ghp_Fak3T0kenF0rLocalAuditDem0nstrati0n1"', "ghp_Fak3T0kenF0rLocalAuditDem0nstrati0n1"),
    "secret-slack-token": ('s = "xoxb-000000000000-000000000000-FakeSlackToken"', "xoxb-000000000000-000000000000-FakeSlackToken"),
    "secret-stripe-live-key": ('k = "sk_live_FAKEfakeFAKEfake0123456789abcd"', "sk_live_FAKEfakeFAKEfake0123456789abcd"),
    "secret-google-api-key": ('g = "AIzaSyFAKE_fake-FAKE_fake-0123456789abc"', "AIzaSyFAKE_fake-FAKE_fake-0123456789abc"),
    "secret-jwt": ('j = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.Zm9vYmFyYmF6cXV4ZmFrZQ"',
                   "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.Zm9vYmFyYmF6cXV4ZmFrZQ"),
    "secret-django-secret-key": ('SECRET_KEY = "django-insecure-9f#k2!qz7w@v1m$x8r4t"', "django-insecure-9f#k2!qz7w@v1m$x8r4t"),
    "secret-generic-assignment": ('db_password = "Sup3rS3cretDbPass!"', "Sup3rS3cretDbPass!"),
    "secret-high-entropy-string": ('webhook_signing_salt = "Zq8mT3xV1nB7cK5pR2wY9hL4"', "Zq8mT3xV1nB7cK5pR2wY9hL4"),
}


@pytest.mark.parametrize("rule_id", sorted(FAKES))
def test_secret_detected_and_masked(rule_id):
    line, value = FAKES[rule_id]
    hits = secrets.scan_lines([line])
    assert [h.pattern.id for h in hits] == [rule_id]
    assert hits[0].masked == value[:4] + "****"
    findings = scan_text(f"# header\n{line}\n# footer\n", "app/config.py")
    assert [f.rule_id for f in findings] == [rule_id]
    for f in findings:
        assert value not in f.snippet and value not in f.match
        assert value[:4] + "****" in f.snippet


def test_mask_function():
    assert secrets.mask("abcdefgh") == "abcd****"


@pytest.mark.parametrize("line", [
    'password = "changeme"',
    'API_KEY = "your_key_here"',
    'api_key = "your-api-key-here"',
    'token = "xxxxxxxxxxxx"',
    'secret = "<your secret>"',
    'password = "${DB_PASSWORD}"',
    'password = "{{ db_password }}"',
    'aws_key = "AKIAIOSFODNN7EXAMPLE"',
    'password = os.environ["DB_PASSWORD"]',
    'password = os.environ.get("DB_PASSWORD", "fallbackpass")',
    'const token = process.env.API_TOKEN || "devtokenvalue";',
    'password = ""',
    'password_field = "password"',
    'SECRET_KEY = "example-secret-key"',
])
def test_placeholders_and_env_lookups_ignored(line):
    assert secrets.scan_lines([line]) == []


def test_provider_key_caught_even_as_env_default():
    hits = secrets.scan_lines(['key = os.environ.get("STRIPE", "sk_live_FAKEfakeFAKEfake0123456789abcd")'])
    assert [h.pattern.id for h in hits] == ["secret-stripe-live-key"]


def test_low_entropy_not_flagged_by_entropy_rule():
    assert secrets.scan_lines(['signing_salt = "aaaabbbbccccdddd"']) == []


def test_shannon_entropy():
    assert secrets.shannon_entropy("aaaa") == 0
    assert secrets.shannon_entropy("abcd") == 2


def test_private_key_body_is_redacted_everywhere():
    text = (
        'DEPLOY_KEY = """-----BEGIN RSA PRIVATE KEY-----\n'
        "MIIBOgIBAAJBAKBODYLINEONEBODYLINEONEBODYLINEONE\n"
        "BODYLINETWOBODYLINETWOBODYLINETWOBODYLINETWO\n"
        '-----END RSA PRIVATE KEY-----"""\n'
        "DEBUG = True\n"
    )
    findings = scan_text(text, "settings.py")
    assert {"secret-private-key", "py-django-debug"} <= {f.rule_id for f in findings}
    for f in findings:
        assert "BODYLINE" not in f.snippet
        assert "BODYLINE" not in f.match


def test_secret_on_context_line_is_masked_in_other_findings():
    text = 'DEBUG = True\napi_token = "Zq8mT3xV1nB7cK5pR2wY9hL4"\n'
    findings = scan_text(text, "settings.py")
    debug = next(f for f in findings if f.rule_id == "py-django-debug")
    assert "Zq8mT3xV1nB7cK5pR2wY9hL4" not in debug.snippet
    assert "Zq8m****" in debug.snippet


def test_single_line_escaped_private_key():
    line = 'K = "-----BEGIN PRIVATE KEY-----\\nSECRETBODY\\n-----END PRIVATE KEY-----"'
    out = secrets.redact_lines([line], secrets.scan_lines([line]))
    assert "SECRETBODY" not in out[0]
