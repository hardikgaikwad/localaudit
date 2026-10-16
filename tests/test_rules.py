import pytest

from localaudit.rules import RULES, get_rule, rules_for

# rule_id -> (known-bad line, safe line)
CASES = {
    "py-django-debug": ("DEBUG = True", "DEBUG = os.environ.get('DEBUG') == '1'"),
    "py-django-allowed-hosts-wildcard": ("ALLOWED_HOSTS = ['*']", "ALLOWED_HOSTS = ['shop.example.com']"),
    "py-eval-exec": ("result = eval(user_input)", "value = ast.literal_eval(user_input)"),
    "py-pickle-loads": ("obj = pickle.loads(blob)", "obj = json.loads(blob)"),
    "py-yaml-load": ("cfg = yaml.load(stream)", "cfg = yaml.load(stream, Loader=yaml.SafeLoader)"),
    "py-subprocess-shell": ("subprocess.run(cmd, shell=True)", "subprocess.run(['ls', '-l'], check=True)"),
    "py-os-system": ("os.system('rm -rf ' + path)", "shutil.rmtree(path)"),
    "py-sql-string-format": ('cursor.execute(f"SELECT * FROM t WHERE id = {uid}")',
                             'cursor.execute("SELECT * FROM t WHERE id = %s", (uid,))'),
    "py-requests-verify-false": ("requests.get(url, verify=False)", "requests.get(url, timeout=5)"),
    "py-weak-password-hash": ("h = hashlib.md5(password.encode()).hexdigest()",
                              "checksum = hashlib.sha256(data).hexdigest()"),
    "py-django-cors-allow-all": ("CORS_ALLOW_ALL_ORIGINS = True", "CORS_ALLOW_ALL_ORIGINS = False"),
    "py-django-csrf-exempt": ("@csrf_exempt", "@require_POST"),
    "py-django-mark-safe": ("return mark_safe(html)", "return format_html('<b>{}</b>', name)"),
    "py-flask-debug": ("app.run(debug=True)", "app.run(host='127.0.0.1')"),
    "js-eval": ("const r = eval(req.query.x);", "const r = JSON.parse(req.query.x);"),
    "js-child-process-exec": ("exec(`ls ${dir}`, cb);", "execFile('ls', [dir], cb);"),
    "js-innerhtml": ("el.innerHTML = msg;", "el.textContent = msg;"),
    "js-dangerously-set-inner-html": ("<div dangerouslySetInnerHTML={{__html: x}} />", "<div>{x}</div>"),
    "js-tls-reject-unauthorized": ("new https.Agent({ rejectUnauthorized: false })",
                                   "new https.Agent({ rejectUnauthorized: true })"),
    "js-math-random-token": ("const token = Math.random().toString(36);",
                             "const token = crypto.randomBytes(32).toString('hex');"),
    "js-cors-wildcard": ("app.use(cors());", "app.use(cors({ origin: 'https://shop.example.com' }));"),
    "gen-internal-address": ("HOST = '192.168.1.10'", "HOST = '8.8.8.8'"),
    "gen-security-todo": ("# TODO: add auth check here", "# TODO: tidy up formatting"),
    "gen-chmod-777": ("chmod 777 /srv/app", "chmod 750 /srv/app"),
}

LANG_FOR = {"py": "python", "js": "javascript", "gen": None}


def test_every_rule_has_a_case():
    assert set(CASES) == {r.id for r in RULES}


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_fires_on_bad_and_not_on_safe(rule_id):
    rule = get_rule(rule_id)
    bad, safe = CASES[rule_id]
    assert rule.search(bad), f"{rule_id} should match: {bad}"
    assert not rule.search(safe), f"{rule_id} should not match: {safe}"


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_applies_to_its_language(rule_id):
    rule = get_rule(rule_id)
    lang = LANG_FOR[rule_id.split("-", 1)[0]]
    assert rule in rules_for(lang)


def test_language_filters():
    assert get_rule("py-eval-exec") not in rules_for("javascript")
    assert get_rule("js-eval") not in rules_for("python")
    assert get_rule("gen-chmod-777") in rules_for(None)


def test_comment_lines_are_skipped_for_code_rules():
    assert not get_rule("py-eval-exec").search("# never call eval(x) here")
    assert not get_rule("js-eval").search("// eval(x) is bad")


def test_rule_metadata_complete():
    for r in RULES:
        assert r.severity in {"critical", "high", "medium", "low", "info"}
        assert r.cwe.startswith("CWE-")
        assert r.description and r.title and r.category
