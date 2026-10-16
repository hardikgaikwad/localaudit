# =====================================================================
# WARNING: INTENTIONALLY INSECURE DEMO CODE FOR LOCALAUDIT. DO NOT USE.
# All tokens below are FAKE.
# =====================================================================
GITHUB_TOKEN = "ghp_Fak3T0kenF0rLocalAuditDem0nstrati0n1"
SLACK_BOT_TOKEN = "xoxb-000000000000-000000000000-FakeSlackTokenForDemo"
STRIPE_SECRET = "sk_live_FAKEfakeFAKEfake0123456789abcd"
GOOGLE_MAPS_KEY = "AIzaSyFAKE_fake-FAKE_fake-0123456789abc"
SERVICE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vLXVzZXIifQ.Zm9vYmFyYmF6cXV4ZmFrZXNpZ25hdHVyZQ"
webhook_signing_salt = "Zq8mT3xV1nB7cK5pR2wY9hL4"

DEPLOY_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
NOTAREALKEYNOTAREALKEYNOTAREALKEYNOTAREALKEYNOTAREALKEYNOTAREAL
-----END RSA PRIVATE KEY-----"""


def run_dev_server(app):
    app.run(host="0.0.0.0", debug=True)
