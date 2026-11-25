"""
app.py - SecurePortal: a Flask application that demonstrates secure coding.

Run locally:   python app.py
Create admin:  flask --app app create-admin
"""
import re
import secrets
import sqlite3
import hashlib
import smtplib
import time
from email.message import EmailMessage
from functools import wraps

import click
from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
import pyotp

import database as db
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

csrf = CSRFProtect(app)   # Every POST request must carry a valid CSRF token
db.init_app(app)

# A throw-away hash used so that "unknown email" and "wrong password" take
# the same amount of time (prevents user enumeration through timing).
DUMMY_HASH = generate_password_hash("not-a-real-password")

# --------------------------------------------------------------------------
# Server-side input validation
# --------------------------------------------------------------------------
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'\-]{1,99}$")
STUDENT_ID_RE = re.compile(r"^[A-Za-z0-9\-]{4,20}$")
PHONE_RE = re.compile(r"^\+?[0-9]{10,15}$")


def normalize_phone(raw):
    """Remove spaces, dashes and brackets so '+91 98765-43210' becomes '+919876543210'."""
    return re.sub(r"[ \-()]", "", raw)


def password_errors(password):
    """Return a list of password-policy violations (empty list = strong password)."""
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if len(password) > 128:
        errors.append("Password must be at most 128 characters long.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain an uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain a lowercase letter.")
    if not re.search(r"[0-9]", password):
        errors.append("Password must contain a number.")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("Password must contain a special character (e.g. @ # $ % !).")
    return errors


def validate_name(name):
    if not NAME_RE.match(name):
        return "Full name must be 2-100 characters: letters, spaces, apostrophes, dots or hyphens only."
    return None


def validate_phone(phone):
    if not PHONE_RE.match(phone):
        return "Phone number must contain 10-15 digits (an optional leading + is allowed)."
    return None


def validate_registration(form, password, confirm):
    errors = []
    if not all(form.values()) or not password or not confirm:
        errors.append("All fields are required.")
        return errors
    for check in (validate_name(form["full_name"]), validate_phone(form["phone"])):
        if check:
            errors.append(check)
    if not STUDENT_ID_RE.match(form["student_id"]):
        errors.append("Student ID must be 4-20 characters: letters, numbers and hyphens only.")
    if len(form["email"]) > 254 or not EMAIL_RE.match(form["email"]):
        errors.append("Please enter a valid email address.")
    errors.extend(password_errors(password))
    if password != confirm:
        errors.append("Password and confirmation do not match.")
    return errors


# --------------------------------------------------------------------------
# Authentication helpers
# --------------------------------------------------------------------------
@app.before_request
def load_logged_in_user():
    """Load the current user from the database on every request.

    Only the user's numeric ID is kept in the (signed) session cookie. Role and
    other details are always read from the database, so deleting an account
    immediately invalidates its session.
    """
    g.user = None
    if session.get("user_id"):
        # Older cookies from before idle-expiry was introduced receive a fresh timestamp.
        last_activity = session.get("last_activity", time.time())
        if time.time() - last_activity > app.config["SESSION_IDLE_MINUTES"] * 60:
            old_id = session.get("user_id")
            db.log_event("session_expired", details=f"Session expired for user id {old_id}", ip_address=request.remote_addr)
            session.clear()
        else:
            session["last_activity"] = time.time()
    user_id = session.get("user_id")
    if user_id is not None:
        g.user = db.get_student_by_id(user_id)
        if g.user is None or session.get("session_version") != g.user["session_version"]:
            # A password reset increments the DB version and revokes older cookies.
            session.clear()
            g.user = None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login"))
        if g.user["role"] != "admin":
            abort(403)  # Logged in, but not authorized
        return view(*args, **kwargs)
    return wrapped


@app.after_request
def set_security_headers(response):
    """Add defensive HTTP headers to every response."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    if request.path.startswith(("/dashboard", "/admin", "/login", "/register", "/security", "/forgot-password", "/reset-password", "/verify-mfa")):
        response.headers["Cache-Control"] = "no-store"  # Don't cache private/account pages
    if app.config.get("SESSION_COOKIE_SECURE"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# --------------------------------------------------------------------------
# Public routes
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))

    form = {"full_name": "", "student_id": "", "email": "", "phone": ""}
    if request.method == "POST":
        # Only these four fields are read. A hidden "role=admin" field sent by an
        # attacker is ignored: new accounts are ALWAYS created as 'student'.
        form = {
            "full_name": request.form.get("full_name", "").strip(),
            "student_id": request.form.get("student_id", "").strip(),
            "email": request.form.get("email", "").strip().lower(),
            "phone": normalize_phone(request.form.get("phone", "").strip()),
        }
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = validate_registration(form, password, confirm)
        if not errors and db.student_exists(form["email"], form["student_id"]):
            errors.append("An account with this email or Student ID already exists.")

        if not errors:
            try:
                new_user_id = db.create_student(form["full_name"], form["student_id"], form["email"],
                                                 form["phone"], generate_password_hash(password), role="student")
            except sqlite3.IntegrityError:
                # Two simultaneous registrations: the UNIQUE constraint is the final safety net.
                errors.append("An account with this email or Student ID already exists.")
            else:
                db.log_event("registration", user_id=new_user_id, email=form["email"], details="Student account created", ip_address=request.remote_addr)
                flash("Registration successful! You can now log in.", "success")
                return redirect(url_for("login"))

        for message in errors:
            flash(message, "danger")
        return render_template("register.html", form=form), 400

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password_input = request.form.get("password", "")
        # Do not truncate credentials: truncation could make a longer incorrect
        # password authenticate as its valid 128-character prefix.
        password = password_input if len(password_input) <= 128 else ("\0" * 129)
        if len(email) > 254:
            email = "invalid-email-too-long"
        remember = request.form.get("remember") == "on"

        # Brute-force protection: limit failed attempts per (email + IP address).
        attempt_key = f"{email}|{request.remote_addr}"
        wait = db.lockout_seconds_remaining(
            attempt_key, app.config["MAX_LOGIN_ATTEMPTS"], app.config["LOGIN_WINDOW_SECONDS"])
        if wait:
            db.log_event("login_lockout", email=email, details="Login rate limit active", ip_address=request.remote_addr)
            flash(f"Too many failed login attempts. Please try again in {wait // 60 + 1} minute(s).", "danger")
            return render_template("login.html", email=email), 429

        user = db.get_student_by_email(email)
        # Always run a hash check (real or dummy) so timing does not reveal valid emails.
        password_ok = check_password_hash(user["password_hash"] if user else DUMMY_HASH, password)

        if user and password_ok:
            db.clear_attempts(attempt_key)
            session.clear()                      # Prevents session fixation
            if user["mfa_enabled"]:
                session["pending_mfa_user_id"] = user["id"]
                session["pending_mfa_since"] = time.time()
                return redirect(url_for("verify_mfa"))
            session["user_id"] = user["id"]
            session["session_version"] = user["session_version"]
            session["last_activity"] = time.time()
            session.permanent = remember
            db.log_event("login_success", user_id=user["id"], email=email, ip_address=request.remote_addr)         # "Remember me" = longer-lived signed cookie
            flash(f"Welcome back, {user['full_name']}!", "success")
            return redirect(url_for("admin_dashboard" if user["role"] == "admin" else "dashboard"))

        db.record_failed_attempt(attempt_key)
        db.log_event("login_failed", email=email, details="Invalid credentials", ip_address=request.remote_addr)
        # One generic message: never reveal whether the email or the password was wrong.
        flash("Invalid email or password.", "danger")
        return render_template("login.html", email=email), 401

    return render_template("login.html", email="")


@app.route("/logout", methods=["POST"])
def logout():
    """Logout is a POST (with CSRF token) so other sites cannot log users out."""
    if g.user:
        db.log_event("logout", user_id=g.user["id"], email=g.user["email"], ip_address=request.remote_addr)
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# --------------------------------------------------------------------------
# Student routes
# --------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=g.user)


@app.route("/profile", methods=["POST"])
@login_required
def update_profile():
    full_name = request.form.get("full_name", "").strip()
    phone = normalize_phone(request.form.get("phone", "").strip())
    errors = [e for e in (validate_name(full_name), validate_phone(phone)) if e]
    if errors:
        for message in errors:
            flash(message, "danger")
    else:
        db.update_profile(g.user["id"], full_name, phone)
        db.log_event("profile_updated", user_id=g.user["id"], email=g.user["email"], ip_address=request.remote_addr)
        flash("Profile updated successfully.", "success")
    return redirect(url_for("dashboard"))


# --------------------------------------------------------------------------
# Admin routes
# --------------------------------------------------------------------------
@app.route("/admin")
@admin_required
def admin_dashboard():
    query = request.args.get("q", "").strip()[:100]
    students = db.list_students(query)
    return render_template("admin.html", students=students, total=db.count_students(), q=query,
                           audit_logs=db.recent_audit_logs(75), failed_count=db.audit_count("login_failed"),
                           lockout_count=db.audit_count("login_lockout"))


@app.route("/admin/students/<int:student_pk>/delete", methods=["POST"])
@admin_required
def delete_student(student_pk):
    target = db.get_student_by_id(student_pk)
    if target is None:
        flash("Student not found.", "warning")
    elif target["role"] == "admin":
        flash("Administrator accounts cannot be deleted from the dashboard.", "danger")
    else:
        db.log_event("student_deleted", user_id=g.user["id"], email=target["email"], details="Deleted by administrator", ip_address=request.remote_addr)
        db.delete_student(student_pk)
        flash(f"Student account '{target['full_name']}' was deleted.", "success")
    return redirect(url_for("admin_dashboard"))


# --------------------------------------------------------------------------
# Additional account security: TOTP MFA and one-time password recovery
# --------------------------------------------------------------------------
def _send_email(recipient, subject, body):
    """Send email only when SMTP is configured; never expose reset tokens in the UI."""
    cfg = app.config
    if not cfg.get("MAIL_SERVER") or not cfg.get("MAIL_DEFAULT_SENDER"):
        app.logger.warning("Email is not configured; message to %s was not sent.", recipient)
        return False
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = cfg["MAIL_DEFAULT_SENDER"]
    message["To"] = recipient
    message.set_content(body)
    try:
        with smtplib.SMTP(cfg["MAIL_SERVER"], cfg["MAIL_PORT"], timeout=10) as server:
            if cfg["MAIL_USE_TLS"]:
                server.starttls()
            if cfg.get("MAIL_USERNAME"):
                server.login(cfg["MAIL_USERNAME"], cfg["MAIL_PASSWORD"])
            server.send_message(message)
        return True
    except (OSError, smtplib.SMTPException):
        app.logger.exception("Unable to send account email")
        return False


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        reset_key = f"reset|{request.remote_addr}"
        reset_wait = db.lockout_seconds_remaining(reset_key, 5, 15 * 60)
        user = db.get_student_by_email(email) if len(email) <= 254 and EMAIL_RE.match(email) else None
        # Same public response regardless of whether the account exists or this
        # source IP has reached its reset-request limit.
        if user and not reset_wait:
            db.record_failed_attempt(reset_key)  # reuse bounded attempt storage as a request counter
            raw_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
            db.create_reset_token(user["id"], token_hash, time.time() + app.config["PASSWORD_RESET_MINUTES"] * 60)
            base_url = app.config.get("PUBLIC_BASE_URL", "").rstrip("/") or request.url_root.rstrip("/")
            link = base_url + url_for("reset_password", token=raw_token)
            sent = _send_email(email, "SecurePortal password reset",
                               f"A password reset was requested. This link expires in {app.config['PASSWORD_RESET_MINUTES']} minutes and can be used once:\n\n{link}\n\nIf you did not request this, ignore this email.")
            db.log_event("password_reset_requested", user_id=user["id"], email=email, details="Email delivery: " + ("sent" if sent else "not configured/failed"), ip_address=request.remote_addr)
        flash("If an account matches that address, password reset instructions will be sent.", "info")
        return redirect(url_for("forgot_password"))
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    record = db.get_reset_token(token_hash)
    if not record:
        return error_page(400, "Invalid or expired link", "Request a new password reset link and try again.")
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        errors = password_errors(password)
        if password != confirm:
            errors.append("Password and confirmation do not match.")
        if errors:
            return render_template("reset_password.html", token=token, errors=errors), 400
        if db.consume_reset_token(token_hash, record["user_id"], generate_password_hash(password)):
            db.log_event("password_reset_completed", user_id=record["user_id"], ip_address=request.remote_addr)
            flash("Password updated. Please log in with your new password.", "success")
            return redirect(url_for("login"))
    return render_template("reset_password.html", token=token, errors=[])


@app.route("/security", methods=["GET", "POST"])
@login_required
def security_settings():
    user = db.get_student_by_id(g.user["id"])
    if request.method == "POST":
        action = request.form.get("action")
        if action == "begin_mfa":
            secret = pyotp.random_base32()
            db.set_mfa_secret(user["id"], secret)
            db.log_event("mfa_setup_started", user_id=user["id"], ip_address=request.remote_addr)
            flash("Authenticator secret generated. Add it to your authenticator app, then verify a code to enable MFA.", "info")
        elif action == "enable_mfa":
            fresh = db.get_student_by_id(user["id"])
            code = request.form.get("code", "").strip()
            if fresh["mfa_secret"] and pyotp.TOTP(fresh["mfa_secret"]).verify(code, valid_window=1):
                db.enable_mfa(user["id"])
                db.log_event("mfa_enabled", user_id=user["id"], ip_address=request.remote_addr)
                flash("Two-factor authentication is now enabled.", "success")
            else:
                flash("Invalid authenticator code. Try again.", "danger")
        elif action == "disable_mfa":
            if not check_password_hash(user["password_hash"], request.form.get("current_password", "")):
                flash("Current password was incorrect.", "danger")
            else:
                db.disable_mfa(user["id"])
                db.log_event("mfa_disabled", user_id=user["id"], ip_address=request.remote_addr)
                flash("Two-factor authentication disabled.", "warning")
        return redirect(url_for("security_settings"))
    user = db.get_student_by_id(g.user["id"])
    provisioning_uri = pyotp.TOTP(user["mfa_secret"]).provisioning_uri(name=user["email"], issuer_name="SecurePortal") if user["mfa_secret"] else None
    return render_template("security.html", user=user, provisioning_uri=provisioning_uri)


@app.route("/verify-mfa", methods=["GET", "POST"])
def verify_mfa():
    pending_id = session.get("pending_mfa_user_id")
    if not pending_id or time.time() - session.get("pending_mfa_since", 0) > 300:
        session.clear()
        flash("Your verification session expired. Please log in again.", "warning")
        return redirect(url_for("login"))
    user = db.get_student_by_id(pending_id)
    if not user or not user["mfa_enabled"]:
        session.clear()
        return redirect(url_for("login"))
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        mfa_key = f"mfa|{pending_id}|{request.remote_addr}"
        wait = db.lockout_seconds_remaining(mfa_key, 5, 10 * 60)
        if wait:
            flash("Too many verification attempts. Please wait before trying again.", "danger")
            return render_template("verify_mfa.html"), 429
        if pyotp.TOTP(user["mfa_secret"]).verify(code, valid_window=1):
            db.clear_attempts(mfa_key)
            session.clear()
            session["user_id"] = user["id"]
            session["session_version"] = user["session_version"]
            session["last_activity"] = time.time()
            db.log_event("login_success_mfa", user_id=user["id"], email=user["email"], ip_address=request.remote_addr)
            return redirect(url_for("admin_dashboard" if user["role"] == "admin" else "dashboard"))
        db.record_failed_attempt(mfa_key)
        db.log_event("mfa_failed", user_id=user["id"], ip_address=request.remote_addr)
        flash("Invalid verification code.", "danger")
    return render_template("verify_mfa.html")


@app.route("/admin/audit.csv")
@admin_required
def export_audit_csv():
    import csv
    import io
    from flask import make_response
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp_utc", "event", "email", "user", "ip_address", "details"])
    for row in db.recent_audit_logs(500):
        values = [row["created_at"], row["event"], row["email"], row["user_name"], row["ip_address"], row["details"]]
        # Neutralize spreadsheet formula prefixes in untrusted CSV fields.
        writer.writerow([("'" + value if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r") else value) for value in values])
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=secureportal-audit.csv"
    response.headers["Cache-Control"] = "no-store"
    return response


# --------------------------------------------------------------------------
# Error handling: friendly pages, never stack traces or internal details
# --------------------------------------------------------------------------
def error_page(code, title, message):
    return render_template("error.html", code=code, title=title, message=message), code


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    return error_page(400, "Security check failed",
                      "Your form session expired or the security token was missing. Go back, refresh the page and try again.")


@app.errorhandler(400)
def handle_400(error):
    return error_page(400, "Bad request", "The request could not be understood.")


@app.errorhandler(403)
def handle_403(error):
    return error_page(403, "Access denied", "You do not have permission to view this page.")


@app.errorhandler(404)
def handle_404(error):
    return error_page(404, "Page not found", "The page you are looking for does not exist.")


@app.errorhandler(405)
def handle_405(error):
    return error_page(405, "Method not allowed", "That action is not allowed on this page.")


@app.errorhandler(413)
def handle_413(error):
    return error_page(413, "Request too large", "The data you sent was too large.")


@app.errorhandler(500)
def handle_500(error):
    # Details go to the server log only (Flask logs the traceback), never to the browser.
    return error_page(500, "Something went wrong", "An unexpected error occurred. Please try again later.")


# --------------------------------------------------------------------------
# Command line tools
# --------------------------------------------------------------------------
@app.cli.command("init-db")
def init_db_command():
    """Create the database tables."""
    db.init_db()
    click.echo("Database initialized.")


@app.cli.command("create-admin")
@click.option("--name", prompt="Admin full name")
@click.option("--email", prompt="Admin email")
@click.password_option(prompt="Admin password (hidden)", confirmation_prompt=True)
def create_admin_command(name, email, password):
    """Create the initial administrator. Credentials are typed at the prompt, never stored in code."""
    name, email = name.strip(), email.strip().lower()
    problems = [e for e in (validate_name(name),) if e]
    if not EMAIL_RE.match(email):
        problems.append("Please enter a valid email address.")
    problems.extend(password_errors(password))
    if problems:
        raise click.ClickException("\n".join(problems))
    if db.get_student_by_email(email):
        raise click.ClickException("An account with that email already exists.")

    admin_id = "ADMIN-" + secrets.token_hex(3).upper()
    db.create_student(name, admin_id, email, "N/A", generate_password_hash(password), role="admin")
    click.echo(f"Administrator account created for {email}.")


if __name__ == "__main__":
    # debug=False: the Werkzeug debugger allows remote code execution and must never be enabled in production.
    app.run(host="127.0.0.1", port=5000, debug=False)
