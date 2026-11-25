# SecurePortal Security Test Plan

Run only against your own local instance at `http://127.0.0.1:5000`.

For each test, record: date, tester, setup, request/action, expected result, actual result, screenshot or tool evidence, and remediation/code reference.

| ID | Area | Test | Expected secure result | Evidence |
|---|---|---|---|---|
| T01 | Registration | Submit missing/invalid fields | Server rejects invalid data; no account created | Form response + DB |
| T02 | Password policy | Try a weak password | Server rejects it regardless of browser validation | Response |
| T03 | Password storage | Inspect `students.password_hash` | Stored value is a salted password hash, not plaintext | SQLite viewer |
| T04 | SQL injection | Use `' OR '1'='1' --` as login/search input | No login bypass, query remains data | Browser + DB |
| T05 | Brute force | Repeatedly submit wrong credentials | Requests are throttled with HTTP 429 | Network tab |
| T06 | User enumeration | Compare unknown email and wrong password messages | Same generic public error | Screenshots |
| T07 | XSS | Submit harmless markup in permitted test fields | Markup is encoded/not executed | Browser |
| T08 | CSRF | Remove CSRF token from a POST | Request rejected; state unchanged | Network tab |
| T09 | Authorization | Student requests `/admin` and admin delete route | HTTP 403; no data changed | Browser |
| T10 | Session | Inspect session cookie | HttpOnly and SameSite set; Secure set on HTTPS | DevTools |
| T11 | Logout | Log out, then revisit `/dashboard` | Redirected to login | Browser |
| T12 | Idle timeout | In local test, wait 30 minutes or temporarily lower config | Session expires and protected route requires login | Browser/log |
| T13 | MFA | Enable TOTP, then log in with valid password only | Login remains pending until valid TOTP code | Browser |
| T14 | MFA throttling | Submit incorrect TOTP repeatedly | Further attempts temporarily blocked | Browser/log |
| T15 | Password reset | Request reset for known and unknown email | Same public response | Screenshots |
| T16 | Reset token | Use a valid link, then reuse it / wait past expiry | Used or expired token rejected | Browser + DB |
| T17 | Audit trail | Perform login, logout, profile update and MFA events | Events appear in admin-only audit trail | Admin page |
| T18 | CSV export | Export audit trail as admin; try as student | Admin gets CSV; student gets 403 | Download/response |
| T19 | Headers | Inspect responses | CSP, X-Frame-Options, nosniff, Referrer-Policy present | DevTools |
| T20 | Error handling | Request missing route / wrong HTTP method | Generic error page; no traceback or secret disclosure | Browser |

## OWASP ZAP / Burp Suite

1. Start the portal locally and configure the scanner proxy to your local browser.
2. Browse the public pages and authenticated student pages you own.
3. Run a passive scan first. Review each alert manually; scanners can produce false positives.
4. If you run active scans, use only the local test instance and a test database. Active scans may create or modify records.
5. Export the report, classify findings by severity, explain false positives, and retest after fixes.
6. Do not claim that a clean scanner report proves the application is vulnerability-free.
