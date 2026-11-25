# SecurePortal — Secure Student Registration & Login Portal

A Flask + SQLite capstone application for demonstrating secure coding, authentication, authorization, defensive database access, auditability and security testing.

> **Important:** This is an educational capstone, not a production-certified identity system. Run it locally for demonstrations. Before internet deployment, obtain a security review, configure HTTPS, secrets, SMTP, trusted hosts, backups, monitoring and a production WSGI server.

## What's included

### Retained from the submitted project
- Existing SecurePortal design, pages, registration and student dashboard.
- Flask backend and SQLite database.
- Server-side registration validation and password hashing (Werkzeug's scrypt format by default).
- Parameterized SQL queries, CSRF protection, Jinja autoescaping and security headers.
- Role-based student/admin access, admin student search and deletion.
- Login throttling and the original automated security test suite.

### Added in this upgrade
- **TOTP two-factor authentication:** users can enable an authenticator app under Dashboard → Security. MFA verification is rate-limited.
- **Password reset:** time-limited, single-use random tokens are stored as SHA-256 hashes. Reset links are sent only when SMTP is configured. The public response does not disclose whether an email exists.
- **Security audit trail:** records registration, successful/failed logins, rate-limit events, logout, profile changes, account deletion, MFA changes, session expiry and password-reset events. Password-reset requests are rate-limited per source IP.
- **Admin security monitoring:** recent audit events and counts for failed login and rate-limit events appear on the admin dashboard.
- **Audit CSV export:** admin-only `/admin/audit.csv`, with spreadsheet-formula prefix neutralization.
- **Idle session expiry:** active authenticated sessions expire after 30 minutes of inactivity.
- **Additive database migration:** existing `students` databases receive MFA columns automatically; new audit and reset-token tables are created without deleting student records.
- Private/account pages receive `Cache-Control: no-store`; HSTS is added when Secure cookies are enabled.

## Project structure

```text
SecurePortal_Upgraded/
├── app.py                    # Flask routes, authentication, security controls
├── config.py                 # Environment-based configuration and secret key
├── database.py               # SQLite schema, migration and parameterized queries
├── requirements.txt
├── .env.example              # Configuration reference (copy values into environment)
├── .gitignore
├── test_security.py          # Existing automated security tests
├── README.md
├── SECURITY_TEST_PLAN.md     # Manual and automated demonstration plan
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── register.html
│   ├── login.html
│   ├── dashboard.html
│   ├── admin.html
│   ├── security.html
│   ├── verify_mfa.html
│   ├── forgot_password.html
│   ├── reset_password.html
│   └── error.html
├── static/css/style.css
├── static/js/script.js
├── static/images/favicon.svg
└── instance/                  # created automatically; database and secret key live here
```

## Run locally (macOS / Linux)

```bash
cd SecurePortal_Upgraded
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

### Windows

```powershell
py -m venv .venv
.venv\Scripts\activate
py -m pip install -r requirements.txt
py app.py
```

The database is created automatically. The new version does **not** include the original uploaded database or its old secret-key file. On first run, a fresh database and new random secret key are generated. If you need your old demo records, back up the original database separately and migrate only the data you intentionally want to keep.

## Create the administrator

In another terminal with the virtual environment activated:

```bash
python -m flask --app app create-admin
```

Follow the hidden password prompt. Admin registration is not available from the public website. Do not hard-code admin credentials in source code.

## Configure password-reset email (optional, needed for real email delivery)

Copy `.env.example` to `.env` as a reference, then set environment variables in your terminal or IDE run configuration. The app does not automatically load `.env`; this avoids adding a dotenv dependency and makes the configuration explicit.

Example (macOS/Linux shell):

```bash
export MAIL_SERVER="smtp.example.com"
export MAIL_PORT="587"
export MAIL_USERNAME="your-smtp-user"
export MAIL_PASSWORD="your-smtp-app-password"
export MAIL_USE_TLS="1"
export MAIL_DEFAULT_SENDER="SecurePortal <no-reply@example.com>"
```

Restart the app after setting these values. Use an SMTP provider's app password/API credential, not your normal mailbox password. Without SMTP configuration, the forgot-password page still gives a generic response, but no email is delivered; check the server log. Do not expose reset tokens in browser messages or screenshots.

## Enable two-factor authentication

1. Register and log in as a student (or admin).
2. Open Dashboard → Security.
3. Select **Set up authenticator app**.
4. Add the displayed manual setup key to a TOTP authenticator app.
5. Enter the six-digit code from the app and enable MFA.
6. Log out and log in again. After the password step, the portal asks for the authenticator code.

The manual secret is sensitive. Do not share it, commit it, or include it in project screenshots. MFA can be disabled only after confirming the account password. This capstone version does not yet implement recovery codes or encrypted-at-rest MFA secrets; discuss these as future improvements.

## Run the existing automated tests

```bash
python test_security.py
python -m unittest -v test_security_extended.py
```

The original suite and the additional upgrade-specific suite creates/uses a temporary test database through `DATABASE_PATH` and a test-only `SECRET_KEY`. It is intended to avoid modifying the normal local database. Review each test's setup before extending it. The original suite was supplied with the project; `test_security_extended.py` adds tests for audit logging, single-use password reset tokens/session revocation, TOTP login, and session-version invalidation. These suites have not been fully executed in this build environment because package installation/network access was unavailable here. Run it on your machine after installing requirements and record the actual output in your report.

## Security controls and where to explain them

| Control | Implementation | Demonstration |
|---|---|---|
| Password storage | Werkzeug password hash (`scrypt` by default) | Inspect `password_hash`; it is not plaintext |
| SQL injection prevention | SQLite parameter placeholders | Try SQL-like text in login/search; it is treated as data |
| CSRF | Flask-WTF CSRF protection | Submit a POST form without its CSRF token; request is rejected |
| XSS | Jinja autoescaping, validation, CSP | Try harmless script markup in a test input; it must not execute |
| Brute-force throttling | Failed attempts per email + IP, bounded time window | Repeat failed login requests and observe HTTP 429 |
| Authorization | `login_required`, `admin_required`, role loaded from DB | Student account requests `/admin` and gets 403 |
| Session controls | Session clear on login/logout, HttpOnly, SameSite, optional Secure, idle expiry | Inspect cookie flags; leave idle and retry protected page |
| MFA | TOTP second factor, limited verification attempts | Enable MFA and demonstrate password + authenticator login |
| Password reset | Random single-use token, hash stored, expiry | Configure SMTP and demonstrate an expired/used link is rejected |
| Audit trail | `audit_logs` table | Perform events and inspect admin dashboard / CSV |
| Security headers | CSP, frame denial, nosniff, referrer policy, no-store | Inspect response headers in browser dev tools |

## Important configuration before any deployment

- Set a long random `SECRET_KEY` in the environment. Rotating it invalidates existing signed sessions and CSRF tokens.
- Set `PUBLIC_BASE_URL` to your canonical HTTPS domain when deployed, to avoid relying on an untrusted Host header for reset links. Set `SESSION_COOKIE_SECURE=1` only when served over HTTPS; otherwise local HTTP testing will not send the session cookie.
- Use HTTPS, a production WSGI server (for example Gunicorn), `debug=False`, and a properly configured reverse proxy.
- Add host validation / trusted-host configuration for your actual deployment domain. Do not trust arbitrary `Host` headers when generating reset URLs.
- Use a production database and centralized rate limiting (for example Redis) if multiple app workers are used. SQLite is appropriate for this small local capstone, not a high-traffic deployment.
- Protect and back up the database. Audit logs contain email addresses and IP addresses; restrict access and define a retention period.
- Add encrypted-at-rest MFA secrets and recovery codes before treating MFA as production-ready.
- Consider email verification, account recovery policy, password breach screening, admin MFA enforcement, security monitoring alerts, and dependency scanning as future enhancements.

## Suggested capstone presentation flow

1. Register a student and show backend validation / password hash storage.
2. Log in, open the student dashboard, update the profile and log out.
3. Show that a student cannot access `/admin`.
4. Perform repeated failed logins and show throttling.
5. Enable TOTP MFA and demonstrate the second login factor.
6. Show admin audit events and export the CSV.
7. Use OWASP ZAP or Burp Suite against your own local test instance and document findings. Do not scan systems you do not own or have permission to test.
8. Present a before/after table: vulnerability, test payload or action, expected secure result, evidence screenshot, and code location.

## Known limitations (be transparent in your viva)

- SQLite and application-level rate limiting are for a local demonstration; production multi-process deployments need shared storage/rate limiting.
- The original login limiter uses email + IP as its key. Add a broader IP-level limiter and account-aware controls for production.
- Email delivery requires SMTP configuration. No reset link is displayed in the UI when SMTP is unavailable.
- MFA secrets are stored in the database in plaintext in this educational version; encrypt them with a managed key before production use.
- MFA has no backup/recovery codes, and admin MFA is not mandatory by policy.
- Email verification is not included. A valid email address format is not proof of mailbox ownership.
- Audit events can contain personal data. Implement retention and access policy before deployment.
- The supplied original automated suite should be run on your machine; do not claim tests passed until you have run them and captured the result.
