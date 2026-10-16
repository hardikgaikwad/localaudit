# =====================================================================
# WARNING: INTENTIONALLY INSECURE DEMO CODE FOR LOCALAUDIT. DO NOT USE.
# All credentials below are FAKE and exist only to trigger the scanner.
# =====================================================================
import os

DEBUG = True
ALLOWED_HOSTS = ["*"]
SECRET_KEY = "django-insecure-9f#k2!qz7w@v1m$x8r4t^p6s0n3b5c&h"

CORS_ALLOW_ALL_ORIGINS = True

# Safe: read from the environment (should NOT be flagged)
DB_PASSWORD = os.environ.get("DB_PASSWORD")
# Placeholder (should NOT be flagged)
STRIPE_API_KEY = "your_key_here"

AWS_ACCESS_KEY_ID = "AKIAZ7FAKEQ3LOCALAUD"
AWS_SECRET_ACCESS_KEY = "q8Rk2vN0fLp5Zx7Tb3Wm9Yc1Hd6Gs4Je0Ua2Oi8E"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": "10.0.12.34",
        "USER": "shop",
        "PASSWORD": "Sup3rS3cretDbPass!",
    }
}

PAYMENT_GATEWAY_URL = "https://payments.corp.internal/api/v1"
