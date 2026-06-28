"""
Vulnerable Flask sample for chat-system / sast-chat demo.

CONTAINS INTENTIONAL SECURITY FLAWS. Do not deploy publicly.
See README.md for the list of seeded vulnerabilities.
"""
import os
import sqlite3
import tempfile
import urllib.request

from flask import Flask, jsonify, render_template, request
from markupsafe import Markup

app = Flask(__name__)

# Vuln #4 — Hardcoded secret (Bandit B105)
SECRET_KEY = "super-secret-do-not-rotate-2024"
app.config["SECRET_KEY"] = SECRET_KEY

DB_PATH = os.path.join(tempfile.gettempdir(), "sample.db")


def init_db() -> None:
    con = sqlite3.connect(DB_PATH)
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT
        );
        INSERT OR IGNORE INTO users (id, name, email)
        VALUES (1, 'alice', 'alice@example.com'),
               (2, 'bob',   'bob@example.com');
        """
    )
    con.commit()
    con.close()


@app.route("/")
def index() -> str:
    # Glassmorphism "giọt nước" demo dashboard (templates/index.html).
    # Purely presentational — the vulnerable endpoints below are unchanged.
    return render_template("index.html")


@app.route("/user")
def user_lookup() -> str:
    """Vuln #1 — SQL injection via f-string concat."""
    user_id = request.args.get("id", "1")
    con = sqlite3.connect(DB_PATH)
    # nosec ignored on purpose — Semgrep + Bandit should still flag this.
    # query = f"SELECT id, name, email FROM users WHERE id = {user_id}"
    # rows = con.execute(query).fetchall()
    query = "SELECT id, name, email FROM users WHERE id = ?"
    rows = con.execute(query, (user_id,)).fetchall()
    con.close()
    return f"<pre>{rows}</pre>"


@app.route("/greet")
def greet() -> str:
    """Vuln #2 — Reflected XSS via Markup() bypassing autoescape."""
    name = request.args.get("name", "world")
    return Markup(f"<h2>Hello, {name}!</h2>")


@app.route("/ping")
def ping() -> str:
    """Vuln #3 — Command injection via os.system."""
    host = request.args.get("host", "127.0.0.1")
    rc = os.system(f"ping -c 1 {host}")  # noqa: S605
    return f"<pre>ping rc={rc}</pre>"


@app.route("/fetch")
def fetch_url() -> str:
    """Vuln #5 — SSRF: arbitrary URL fetch with no allowlist."""
    target = request.args.get("url", "https://example.com")
    with urllib.request.urlopen(target, timeout=5) as resp:  # noqa: S310
        body = resp.read(2000)
    return f"<pre>{body!r}</pre>"


@app.route("/health")
def health():
    # Flask 1.0 does not auto-jsonify dict returns; use jsonify explicitly
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    # Vuln-adjacent: debug=True exposes Werkzeug debugger in some configs.
    app.run(host="0.0.0.0", port=5000, debug=False)
