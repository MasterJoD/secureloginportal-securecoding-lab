"""
test_security.py - Automated security tests for SecurePortal (local use only).

Run:  python test_security.py
Uses a temporary database, so your real instance/students.db is never touched.
Each test prints: the vulnerability, the protection, and the expected result.
"""
import os
import re
import sqlite3
import tempfile
import unittest

# Use a throw-away database and secret key for the test run.
_TMP = tempfile.mkdtemp()
os.environ["DATABASE_PATH"] = os.path.join(_TMP, "test.db")
os.environ["SECRET_KEY"] = "test-only-secret-key"

import app as portal                       # noqa: E402
import database as db                      # noqa: E402
from werkzeug.security import check_password_hash, generate_password_hash  # noqa: E402

STRONG = "Str0ng!Pass"
TOKEN_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def explain(vuln, protection, expected):
    print(f"\n  Vulnerability : {vuln}\n  Protection    : {protection}\n  Expected      : {expected}")


class SecurePortalTests(unittest.TestCase):
    def setUp(self):
        self.app = portal.app
        self.app.config["TESTING"] = False   # keep real error handling
        with self.app.app_context():
            db.init_db()
            conn = db.get_db()
            conn.execute("DELETE FROM students")
            conn.execute("DELETE FROM login_attempts")
            conn.commit()
            db.create_student("Site Admin", "ADMIN-TEST", "admin@example.com", "N/A",
                              generate_password_hash(STRONG), role="admin")
        self.client = self.app.test_client()

    # ---------- helpers ----------
    def token(self, client, url="/login"):
        return TOKEN_RE.search(client.get(url).get_data(as_text=True)).group(1)

    def register(self, client=None, **over):
        client = client or self.client
        data = {"full_name": "Asha Verma", "student_id": "STU1001", "email": "asha@example.com",
                "phone": "+919876543210", "password": STRONG, "confirm_password": STRONG}
        data.update(over)
        data["csrf_token"] = self.token(client, "/register")
        return client.post("/register", data=data)

    def login(self, client, email, password, remember=False):
        data = {"email": email, "password": password, "csrf_token": self.token(client, "/login")}
        if remember:
            data["remember"] = "on"
        return client.post("/login", data=data)

    def logout(self, client):
        return client.post("/logout", data={"csrf_token": self.token(client, "/dashboard")})

    def rows(self, sql, args=()):
        with self.app.app_context():
            return db.get_db().execute(sql, args).fetchall()

    # ---------- tests ----------
    def test_01_sql_injection(self):
        explain("SQL injection - attacker input changes the SQL query",
                "Parameterized queries ('?' placeholders) + server-side validation",
                "Payloads never log in, never dump records, and the table survives")
        self.register()
        for payload in ("' OR '1'='1' --", "asha@example.com' OR '1'='1", "admin@example.com'--"):
            r = self.login(self.client, payload, "anything")
            self.assertEqual(r.status_code, 401)
            self.assertIn("Invalid email or password", r.get_data(as_text=True))
        r = self.register(full_name="x'); DROP TABLE students;--", student_id="STU2002", email="b@example.com")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(len(self.rows("SELECT * FROM students")), 2)    # table intact
        admin = self.app.test_client()
        self.login(admin, "admin@example.com", STRONG)
        page = admin.get("/admin?q=' OR '1'='1").get_data(as_text=True)
        self.assertNotIn("Asha Verma", page)                             # treated as plain text

    def test_02_invalid_logins_and_rate_limit(self):
        explain("Brute-force / password guessing",
                "Generic error message + lockout after 5 failed attempts per email+IP",
                "401 for wrong passwords, then 429 lockout even for the correct password")
        self.register()
        for _ in range(5):
            self.assertEqual(self.login(self.client, "asha@example.com", "Wrong!Pass1").status_code, 401)
        locked = self.login(self.client, "asha@example.com", STRONG)
        self.assertEqual(locked.status_code, 429)
        self.assertIn("Too many failed login attempts", locked.get_data(as_text=True))

    def test_03_weak_passwords_rejected(self):
        explain("Weak passwords are easy to guess",
                "Server-side password policy (8+ chars, upper, lower, digit, special)",
                "Each weak password returns 400 and no account is created")
        for i, weak in enumerate(["short1!", "alllowercase1!", "ALLUPPERCASE1!", "NoNumbers!!", "NoSpecial123"]):
            r = self.register(student_id=f"WEAK{i}00", email=f"weak{i}@example.com", password=weak, confirm_password=weak)
            self.assertEqual(r.status_code, 400, weak)
        self.assertEqual(len(self.rows("SELECT * FROM students WHERE role='student'")), 0)
        r = self.register(confirm_password="Different1!")
        self.assertIn("do not match", r.get_data(as_text=True))

    def test_04_duplicate_registration(self):
        explain("Duplicate accounts / account takeover by re-registering",
                "Existence check + UNIQUE constraints on email and student_id",
                "Second registration with the same email or Student ID is rejected")
        self.assertEqual(self.register().status_code, 302)
        self.assertEqual(self.register(student_id="STU9999").status_code, 400)             # same email
        self.assertEqual(self.register(email="other@example.com").status_code, 400)        # same Student ID
        self.assertEqual(self.register(email="ASHA@EXAMPLE.COM", student_id="STU7777").status_code, 400)
        self.assertEqual(len(self.rows("SELECT * FROM students WHERE role='student'")), 1)

    def test_05_unauthorized_dashboard(self):
        explain("Broken access control - viewing private pages without logging in",
                "login_required decorator checks the session on every request",
                "Anonymous visitor is redirected to /login")
        r = self.client.get("/dashboard")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])

    def test_06_unauthorized_admin(self):
        explain("Privilege escalation - students opening admin pages / self-registering as admin",
                "admin_required decorator (role read from DB) + role is never taken from user input",
                "Anonymous -> redirect, student -> 403, forged role=admin field is ignored")
        self.assertEqual(self.client.get("/admin").status_code, 302)
        self.register(role="admin")                                  # attacker adds hidden role field
        self.assertEqual(self.rows("SELECT role FROM students WHERE email='asha@example.com'")[0]["role"], "student")
        self.login(self.client, "asha@example.com", STRONG)
        self.assertEqual(self.client.get("/admin").status_code, 403)

    def test_07_xss(self):
        explain("Stored/reflected XSS - attacker script runs in another user's browser",
                "Input validation + Jinja2 autoescaping + Content-Security-Policy header",
                "Script payloads are rejected, and any that reach the DB render as harmless text")
        r = self.register(full_name="<script>alert(1)</script>")
        self.assertEqual(r.status_code, 400)
        # Simulate a malicious value that bypassed validation (e.g. imported data).
        with self.app.app_context():
            db.create_student("<script>alert('x')</script>", "XSS-0001", "x@example.com", "1234567890",
                              generate_password_hash(STRONG))
        admin = self.app.test_client()
        self.login(admin, "admin@example.com", STRONG)
        page = admin.get("/admin?q=<script>alert(2)</script>")
        html = page.get_data(as_text=True)
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("script-src 'self'", page.headers["Content-Security-Policy"])

    def test_08_csrf(self):
        explain("CSRF - another website tricks a logged-in user's browser into submitting a form",
                "Flask-WTF CSRF token required on every POST",
                "POST without a token returns 400 and changes nothing")
        self.register()
        r = self.client.post("/login", data={"email": "asha@example.com", "password": STRONG})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.client.post("/register", data={"full_name": "Eve Hacker"}).status_code, 400)
        admin = self.app.test_client()
        self.login(admin, "admin@example.com", STRONG)
        pk = self.rows("SELECT id FROM students WHERE email='asha@example.com'")[0]["id"]
        self.assertEqual(admin.post(f"/admin/students/{pk}/delete").status_code, 400)
        self.assertEqual(len(self.rows("SELECT * FROM students WHERE id=?", (pk,))), 1)
        self.assertEqual(admin.post("/logout").status_code, 400)

    def test_09_password_hashing(self):
        explain("Plaintext / weakly stored passwords leak if the database is stolen",
                "Werkzeug salted hashing (generate_password_hash)",
                "Stored value is a salted hash, never the password; same password -> different hashes")
        self.register()
        self.register(student_id="STU1002", email="ravi@example.com", full_name="Ravi Kumar")
        hashes = [r["password_hash"] for r in self.rows("SELECT password_hash FROM students WHERE role='student'")]
        self.assertEqual(len(hashes), 2)
        for h in hashes:
            self.assertNotIn(STRONG, h)
            self.assertRegex(h, r"^(scrypt|pbkdf2):")
            self.assertTrue(check_password_hash(h, STRONG))
            self.assertFalse(check_password_hash(h, "Wrong!Pass1"))
        self.assertNotEqual(hashes[0], hashes[1])      # unique salts

    def test_10_session_and_logout(self):
        explain("Session theft / sessions that survive logout",
                "HttpOnly + SameSite cookies, session cleared on login and logout, user re-loaded from DB",
                "Dashboard works after login, redirects after logout, and dies if the account is deleted")
        self.register()
        r = self.login(self.client, "asha@example.com", STRONG)
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.logout(self.client).status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        # Deleting an account invalidates its live session immediately.
        self.login(self.client, "asha@example.com", STRONG)
        pk = self.rows("SELECT id FROM students WHERE email='asha@example.com'")[0]["id"]
        admin = self.app.test_client()
        self.login(admin, "admin@example.com", STRONG)
        token = self.token(admin, "/admin")
        self.assertEqual(admin.post(f"/admin/students/{pk}/delete", data={"csrf_token": token}).status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_11_error_pages_and_headers(self):
        explain("Information leakage through error pages",
                "Custom error handlers + security headers",
                "404/405 pages show no stack traces; X-Frame-Options and nosniff are set")
        r = self.client.get("/no-such-page")
        body = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 404)
        for leak in ("Traceback", "sqlite", "SECRET_KEY", "werkzeug"):
            self.assertNotIn(leak, body)
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(self.client.get("/logout").status_code, 405)


if __name__ == "__main__":
    unittest.main(verbosity=2)
