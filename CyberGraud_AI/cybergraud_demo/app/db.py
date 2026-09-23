from __future__ import annotations

import sqlite3
from pathlib import Path
import hashlib
import hmac
import os


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return "pbkdf2_sha256$310000$" + salt.hex() + "$" + digest.hex()

def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, rounds, salt_hex, digest_hex = encoded.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(actual.hex(), digest_hex)
    except Exception:
        return False

DB_PATH = Path(__file__).resolve().parent.parent / "cybergraud.db"


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = connect()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'Student',
        points INTEGER NOT NULL DEFAULT 0,
        badges_json TEXT NOT NULL DEFAULT '[]',
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_login TEXT
    );
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        mode TEXT NOT NULL,
        source TEXT,
        target TEXT,
        attack_type TEXT NOT NULL,
        prediction TEXT NOT NULL,
        risk TEXT NOT NULL,
        confidence REAL NOT NULL,
        malicious_probability REAL NOT NULL DEFAULT 0,
        features_json TEXT NOT NULL,
        explanation_json TEXT NOT NULL,
        recommendations_json TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS knowledge_base (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_type TEXT UNIQUE NOT NULL,
        description TEXT NOT NULL,
        prevention TEXT NOT NULL,
        severity TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS model_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        algorithm TEXT NOT NULL,
        samples INTEGER NOT NULL,
        accuracy REAL NOT NULL,
        trained_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        trained_by INTEGER
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    """)

    # Lightweight migration for databases created by the earlier demo.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "badges_json" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN badges_json TEXT NOT NULL DEFAULT '[]'")
    if "active" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
    if "last_login" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN last_login TEXT")
    ecols = {r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()}
    if "malicious_probability" not in ecols:
        conn.execute("ALTER TABLE events ADD COLUMN malicious_probability REAL NOT NULL DEFAULT 0")

    seeds = [
        ("SQL Injection", "Untrusted input changes the meaning of a database query.", "Use parameterized queries; validate input; least-privilege DB accounts; WAF.", "High"),
        ("XSS", "Untrusted content is interpreted as executable browser content.", "Output encoding; input sanitization; Content Security Policy; secure cookies.", "High"),
        ("Brute Force", "Repeated authentication attempts indicate credential guessing.", "Rate limiting; MFA; CAPTCHA; account lockout and anomaly detection.", "Medium"),
        ("DDoS", "Abnormally high traffic can exhaust application or network resources.", "Rate limiting; CDN; autoscaling; upstream filtering; traffic monitoring.", "High"),
        ("Normal", "Baseline activity with no strong malicious indicators.", "Continue monitoring, logging and periodic security review.", "Low"),
    ]
    for row in seeds:
        conn.execute("INSERT OR IGNORE INTO knowledge_base(attack_type,description,prevention,severity) VALUES(?,?,?,?)", row)

    defaults = [
        ("System Admin", "admin@cybergraud.local", hash_password("Admin@123"), "Admin"),
        ("Demo Student", "student@cybergraud.local", hash_password("Student@123"), "Student"),
        ("Demo Website Owner", "owner@cybergraud.local", hash_password("Owner@123"), "Website Owner"),
    ]
    for name, email, ph, role in defaults:
        conn.execute("INSERT OR IGNORE INTO users(name,email,password_hash,role) VALUES(?,?,?,?)", (name, email, ph, role))
    if conn.execute("SELECT COUNT(*) FROM model_runs").fetchone()[0] == 0:
        conn.execute("INSERT INTO model_runs(algorithm,samples,accuracy) VALUES(?,?,?)", ("Random Forest", 1750, 0.97))
    conn.commit()
    conn.close()


def get_user_by_email(email):
    conn = connect(); row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone(); conn.close(); return row


def get_user(user_id):
    conn = connect(); row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone(); conn.close(); return row


def public_user(row):
    d = dict(row)
    d.pop("password_hash", None)
    return d
