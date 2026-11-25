"""
database.py - All SQLite access for SecurePortal.

SECURITY NOTE: every query uses '?' placeholders (parameterized queries).
User input is never concatenated into SQL strings, which prevents SQL injection.
"""
import math
import os
import sqlite3
import time

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS students (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name     TEXT NOT NULL,
    student_id    TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    phone         TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'admin')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    mfa_secret    TEXT,
    mfa_enabled   INTEGER NOT NULL DEFAULT 0,
    session_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_key  TEXT NOT NULL,
    attempted_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_key ON login_attempts (attempt_key);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    email TEXT,
    event TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES students(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_logs(event);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES students(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    email TEXT,
    event TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES students(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_logs(event);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES students(id) ON DELETE CASCADE
);
"""


def get_db() -> sqlite3.Connection:
    """Open one connection per request and reuse it."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(exception=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    """Create tables if they do not exist yet."""
    path = current_app.config["DATABASE"]
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = get_db()
    conn.executescript(SCHEMA)
    # Safe additive migration for databases created by the original project.
    columns = {row[1] for row in conn.execute("PRAGMA table_info(students)").fetchall()}
    if "mfa_secret" not in columns:
        conn.execute("ALTER TABLE students ADD COLUMN mfa_secret TEXT")
    if "mfa_enabled" not in columns:
        conn.execute("ALTER TABLE students ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0")
    if "session_version" not in columns:
        conn.execute("ALTER TABLE students ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
    conn.commit()


def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()


# --------------------------------------------------------------------------
# Student queries (all parameterized)
# --------------------------------------------------------------------------
def create_student(full_name, student_id, email, phone, password_hash, role="student"):
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO students (full_name, student_id, email, phone, password_hash, role) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (full_name, student_id, email, phone, password_hash, role),
    )
    conn.commit()
    return cur.lastrowid


def student_exists(email, student_id):
    row = get_db().execute(
        "SELECT 1 FROM students WHERE email = ? OR student_id = ? COLLATE NOCASE",
        (email, student_id),
    ).fetchone()
    return row is not None


def get_student_by_email(email):
    return get_db().execute("SELECT * FROM students WHERE email = ?", (email,)).fetchone()


def get_student_by_id(pk):
    return get_db().execute("SELECT * FROM students WHERE id = ?", (pk,)).fetchone()


def update_profile(pk, full_name, phone):
    conn = get_db()
    conn.execute("UPDATE students SET full_name = ?, phone = ? WHERE id = ?", (full_name, phone, pk))
    conn.commit()


def count_students():
    return get_db().execute("SELECT COUNT(*) FROM students WHERE role = 'student'").fetchone()[0]


def _escape_like(text):
    """Escape LIKE wildcards so a search for '%' matches a literal '%'."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def list_students(search=""):
    """Return student records, optionally filtered by name, student ID or email."""
    if search:
        pattern = f"%{_escape_like(search)}%"
        return get_db().execute(
            "SELECT * FROM students WHERE role = 'student' AND ("
            "full_name LIKE ? ESCAPE '\\' OR student_id LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\') "
            "ORDER BY created_at DESC, id DESC",
            (pattern, pattern, pattern),
        ).fetchall()
    return get_db().execute(
        "SELECT * FROM students WHERE role = 'student' ORDER BY created_at DESC, id DESC"
    ).fetchall()


def delete_student(pk):
    conn = get_db()
    conn.execute("DELETE FROM students WHERE id = ? AND role = 'student'", (pk,))
    conn.commit()


# --------------------------------------------------------------------------
# Brute-force protection (failed login tracking)
# --------------------------------------------------------------------------
def record_failed_attempt(key):
    conn = get_db()
    conn.execute("INSERT INTO login_attempts (attempt_key, attempted_at) VALUES (?, ?)", (key, time.time()))
    conn.commit()


def lockout_seconds_remaining(key, max_attempts, window_seconds):
    """Return 0 if the key may try to log in, otherwise seconds until it may retry."""
    conn = get_db()
    now = time.time()
    conn.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (now - window_seconds,))
    conn.commit()
    count, oldest = conn.execute(
        "SELECT COUNT(*), MIN(attempted_at) FROM login_attempts WHERE attempt_key = ?", (key,)
    ).fetchone()
    if count >= max_attempts:
        return max(1, math.ceil(oldest + window_seconds - now))
    return 0


def clear_attempts(key):
    conn = get_db()
    conn.execute("DELETE FROM login_attempts WHERE attempt_key = ?", (key,))
    conn.commit()


# --------------------------------------------------------------------------
# Audit trail, MFA and password recovery helpers
# --------------------------------------------------------------------------
def log_event(event, user_id=None, email=None, details=None, ip_address=None):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_logs (user_id, email, event, details, ip_address) VALUES (?, ?, ?, ?, ?)",
        (user_id, email, event, (details or "")[:500], (ip_address or "")[:64]),
    )
    conn.commit()


def recent_audit_logs(limit=100):
    return get_db().execute(
        "SELECT audit_logs.*, students.full_name AS user_name FROM audit_logs "
        "LEFT JOIN students ON students.id = audit_logs.user_id "
        "ORDER BY audit_logs.id DESC LIMIT ?", (min(max(int(limit), 1), 500),)
    ).fetchall()


def audit_count(event=None):
    if event:
        return get_db().execute("SELECT COUNT(*) FROM audit_logs WHERE event = ?", (event,)).fetchone()[0]
    return get_db().execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]


def set_mfa_secret(user_id, secret):
    conn = get_db()
    conn.execute("UPDATE students SET mfa_secret = ?, mfa_enabled = 0 WHERE id = ?", (secret, user_id))
    conn.commit()


def enable_mfa(user_id):
    conn = get_db()
    conn.execute("UPDATE students SET mfa_enabled = 1 WHERE id = ? AND mfa_secret IS NOT NULL", (user_id,))
    conn.commit()


def disable_mfa(user_id):
    conn = get_db()
    conn.execute("UPDATE students SET mfa_enabled = 0, mfa_secret = NULL WHERE id = ?", (user_id,))
    conn.commit()


def create_reset_token(user_id, token_hash, expires_at):
    conn = get_db()
    conn.execute("UPDATE password_reset_tokens SET used = 1 WHERE user_id = ?", (user_id,))
    conn.execute("INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
                 (user_id, token_hash, expires_at))
    conn.commit()


def get_reset_token(token_hash):
    return get_db().execute(
        "SELECT * FROM password_reset_tokens WHERE token_hash = ? AND used = 0 AND expires_at > ?",
        (token_hash, time.time())
    ).fetchone()


def consume_reset_token(token_hash, user_id, password_hash):
    conn = get_db()
    row = conn.execute(
        "SELECT id FROM password_reset_tokens WHERE token_hash = ? AND user_id = ? AND used = 0 AND expires_at > ?",
        (token_hash, user_id, time.time())
    ).fetchone()
    if not row:
        return False
    # Conditional consumption ensures a reset token can only win once, even
    # if two reset submissions arrive close together.
    changed = conn.execute(
        "UPDATE password_reset_tokens SET used = 1 WHERE id = ? AND used = 0 AND expires_at > ?",
        (row['id'], time.time())
    ).rowcount
    if changed != 1:
        conn.rollback()
        return False
    conn.execute("UPDATE students SET password_hash = ?, session_version = session_version + 1 WHERE id = ?",
                 (password_hash, user_id))
    conn.commit()
    return True
