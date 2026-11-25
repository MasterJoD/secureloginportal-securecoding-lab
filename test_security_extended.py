"""Additional tests for SecurePortal 2.0 features.

Run with: python -m unittest -v test_security_extended.py
Uses an isolated temporary SQLite database and test-only secret key.
"""
import hashlib
import os
import re
import tempfile
import time
import unittest

_TMP = tempfile.mkdtemp(prefix="secureportal_extended_")
os.environ["DATABASE_PATH"] = os.path.join(_TMP, "extended_test.db")
os.environ["SECRET_KEY"] = "extended-tests-only-secret-key"

import pyotp
import app as portal
import database as db
from werkzeug.security import check_password_hash, generate_password_hash

TOKEN_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
PASSWORD = "Str0ng!Pass"


class SecurePortalExtendedTests(unittest.TestCase):
    def setUp(self):
        self.app = portal.app
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
        with self.app.app_context():
            db.init_db()
            conn = db.get_db()
            conn.execute("DELETE FROM password_reset_tokens")
            conn.execute("DELETE FROM audit_logs")
            conn.execute("DELETE FROM login_attempts")
            conn.execute("DELETE FROM students")
            conn.commit()
            self.user_id = db.create_student(
                "Test Student", "STU10001", "student@example.com", "+919876543210",
                generate_password_hash(PASSWORD), role="student"
            )
        self.client = self.app.test_client()

    def token(self, path):
        response = self.client.get(path)
        match = TOKEN_RE.search(response.get_data(as_text=True))
        self.assertIsNotNone(match, f"No CSRF token found on {path}")
        return match.group(1)

    def login(self):
        return self.client.post("/login", data={
            "email": "student@example.com", "password": PASSWORD,
            "csrf_token": self.token("/login")
        })

    def test_audit_event_is_recorded(self):
        with self.app.app_context():
            db.log_event("test_event", user_id=self.user_id, email="student@example.com",
                         details="audit test", ip_address="127.0.0.1")
            row = db.get_db().execute("SELECT * FROM audit_logs WHERE event = 'test_event'").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["email"], "student@example.com")

    def test_password_reset_token_is_single_use_and_revokes_sessions(self):
        with self.app.app_context():
            old = db.get_student_by_id(self.user_id)
            raw = "test-reset-token-that-is-long-and-random"
            digest = hashlib.sha256(raw.encode()).hexdigest()
            db.create_reset_token(self.user_id, digest, time.time() + 300)
            self.assertTrue(db.consume_reset_token(digest, self.user_id, generate_password_hash("NewPass!123")))
            self.assertFalse(db.consume_reset_token(digest, self.user_id, generate_password_hash("OtherPass!123")))
            updated = db.get_student_by_id(self.user_id)
            self.assertEqual(updated["session_version"], old["session_version"] + 1)
            self.assertTrue(check_password_hash(updated["password_hash"], "NewPass!123"))

    def test_totp_mfa_is_required_after_password(self):
        with self.app.app_context():
            secret = pyotp.random_base32()
            db.set_mfa_secret(self.user_id, secret)
            db.enable_mfa(self.user_id)
        response = self.login()
        self.assertEqual(response.status_code, 302)
        self.assertIn("verify-mfa", response.headers["Location"])
        response = self.client.post("/verify-mfa", data={
            "code": pyotp.TOTP(secret).now(), "csrf_token": self.token("/verify-mfa")
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

    def test_session_version_change_revokes_old_cookie(self):
        self.assertEqual(self.login().status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        with self.app.app_context():
            conn = db.get_db()
            conn.execute("UPDATE students SET session_version = session_version + 1 WHERE id = ?", (self.user_id,))
            conn.commit()
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.headers["Location"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
