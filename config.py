"""
config.py - Central configuration for SecurePortal.

Secrets are NEVER hard-coded here. The secret key comes from the SECRET_KEY
environment variable, or is generated once and stored in instance/.secret_key
(a file that is excluded from version control and only readable by the owner).
"""
import os
import secrets
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")


def _load_secret_key() -> str:
    """Return the Flask secret key (used to sign session cookies and CSRF tokens)."""
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key

    os.makedirs(INSTANCE_DIR, exist_ok=True)
    key_path = os.path.join(INSTANCE_DIR, ".secret_key")
    if os.path.exists(key_path):
        with open(key_path, "r", encoding="utf-8") as f:
            return f.read().strip()

    # First run: generate a cryptographically strong random key.
    key = secrets.token_hex(32)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key)
    return key


class Config:
    SECRET_KEY = _load_secret_key()
    DATABASE = os.environ.get("DATABASE_PATH", os.path.join(INSTANCE_DIR, "students.db"))

    # ---- Session / cookie security ----
    SESSION_COOKIE_NAME = "secureportal_session"
    SESSION_COOKIE_HTTPONLY = True      # JavaScript cannot read the cookie (limits XSS damage)
    SESSION_COOKIE_SAMESITE = "Lax"     # Cookie is not sent on cross-site POSTs (limits CSRF)
    # 'Secure' only works over HTTPS. Keep it off for http://127.0.0.1 during
    # development and set SESSION_COOKIE_SECURE=1 when deploying behind HTTPS.
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
    REMEMBER_DAYS = 7
    PERMANENT_SESSION_LIFETIME = timedelta(days=REMEMBER_DAYS)

    # ---- CSRF ----
    WTF_CSRF_TIME_LIMIT = 3600          # CSRF tokens expire after 1 hour

    # ---- Request size limit (blocks huge payloads) ----
    MAX_CONTENT_LENGTH = 16 * 1024      # 16 KB is plenty for these forms

    # ---- Brute-force protection ----
    MAX_LOGIN_ATTEMPTS = 5              # failed attempts allowed ...
    LOGIN_WINDOW_SECONDS = 15 * 60      # ... within this time window
    SESSION_IDLE_MINUTES = 30
    PASSWORD_RESET_MINUTES = 20
    PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "")
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "1") == "1"
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", os.environ.get("MAIL_USERNAME", ""))
