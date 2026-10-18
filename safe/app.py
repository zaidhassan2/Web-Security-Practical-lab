"""
Campus Portal — SAFE version  (port 5002)
==========================================
This file is the hardened twin of vulnerable/app.py.
Every fix is annotated with a # FIX comment that mirrors the # VULN comment
in the vulnerable version.  Read them side-by-side.
"""
import pathlib, secrets, sqlite3
from flask import (
    Flask, g, render_template, request, redirect,
    url_for, session, abort
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
BASE = pathlib.Path(__file__).parent
TEMPLATE_DIR = BASE / "templates"
STATIC_DIR   = BASE / "static"

app = Flask(__name__, template_folder=str(TEMPLATE_DIR), static_folder=str(STATIC_DIR))

# FIX 0: Random secret key generated at startup — cannot be predicted or hardcoded
app.secret_key = secrets.token_hex(32)

# FIX 0b: SameSite=Strict — the session cookie is never sent on cross-site requests
app.config["SESSION_COOKIE_NAME"] = "safe_session"
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_HTTPONLY"] = True
# SESSION_COOKIE_SECURE is intentionally False because we run on HTTP localhost.
# In production this must be True (HTTPS only).


# ---------------------------------------------------------------------------
# Security headers — applied to every response
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    # FIX 0c: Content-Security-Policy blocks inline scripts and external resources
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
DB_PATH = BASE / "portal.db"


def get_db():
    if "db" not in g:
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        g.db = con
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db:
        db.close()


# ---------------------------------------------------------------------------
# CSRF helpers
# ---------------------------------------------------------------------------
def get_csrf_token():
    """Return (or create) the per-session CSRF token."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def verify_csrf():
    """Abort 403 if the submitted CSRF token does not match the session token."""
    submitted = request.form.get("csrf_token", "")
    expected  = session.get("csrf_token", "")
    # FIX 0d: Use constant-time comparison to prevent timing attacks
    if not expected or not submitted or not secrets.compare_digest(submitted, expected):
        abort(403)


# ---------------------------------------------------------------------------
# Context processor — inject user and CSRF token into every template
# ---------------------------------------------------------------------------
@app.context_processor
def inject_user():
    uid = session.get("user_id")
    user = None
    if uid:
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return {
        "current_user": user,
        "version": "SAFE",
        "csrf_token": get_csrf_token(),
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

# ---------- Login -----------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()

        # FIX 1a: Parameterized query — user input is never interpolated into SQL
        row = db.execute(
            "SELECT id, username, role FROM users WHERE username=? AND password=?",
            (username, password),
        ).fetchone()

        if row:
            session.clear()
            session["user_id"]  = row["id"]
            session["username"] = row["username"]
            session["role"]     = row["role"]
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
    return render_template("login.html", error=error)


# ---------- Logout ----------------------------------------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- Dashboard -------------------------------------------------------
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    error = None
    success = None

    if request.method == "POST":
        # FIX 0e: CSRF token verified before processing any state-changing POST
        verify_csrf()

        body = request.form.get("body", "").strip()
        if body:
            # FIX 1b: Escape once at render time with Jinja autoescape (no |safe).
            safe_body = body[:2000]
            db.execute(
                "INSERT INTO comments (user_id, username, body) VALUES (?, ?, ?)",
                (session["user_id"], session["username"], safe_body),
            )
            db.commit()
            success = "Comment posted."
        else:
            error = "Comment body cannot be empty."

    announcements = db.execute(
        "SELECT * FROM announcements ORDER BY created_at DESC"
    ).fetchall()
    comments = db.execute(
        "SELECT * FROM comments ORDER BY created_at DESC LIMIT 30"
    ).fetchall()
    my_courses = db.execute(
        "SELECT c.code, c.title FROM courses c "
        "JOIN enrollments e ON c.id = e.course_id "
        "WHERE e.user_id = ?",
        (session["user_id"],),
    ).fetchall()

    return render_template(
        "dashboard.html",
        announcements=announcements,
        comments=comments,
        my_courses=my_courses,
        error=error,
        success=success,
    )


# ---------- Course search ---------------------------------------------------
@app.route("/search")
def search():
    if "user_id" not in session:
        return redirect(url_for("login"))

    term = request.args.get("q", "")
    db = get_db()
    courses = []
    db_error = None

    if term:
        # FIX 2a: Parameterized LIKE query — wildcards handled by the driver, not string format
        courses = db.execute(
            "SELECT * FROM courses WHERE title LIKE ? OR code LIKE ?",
            (f"%{term}%", f"%{term}%"),
        ).fetchall()
        # FIX 2b: No raw DB errors echoed — error details stay server-side

    # FIX 1c: term rendered with Jinja autoescape (no |safe) — reflected XSS blocked
    return render_template("search.html", courses=courses, term=term, db_error=db_error)


# ---------- Profile ---------------------------------------------------------
@app.route("/profile")
@app.route("/profile/<uid>")
def profile(uid=None):
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    if uid is None:
        uid = session["user_id"]

    # FIX 2c: Coerce uid to int — non-integer values (e.g. UNION payloads) rejected immediately
    try:
        uid = int(uid)
    except (ValueError, TypeError):
        abort(400)

    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        abort(404)

    enrollments = db.execute(
        "SELECT c.code, c.title, c.instructor FROM courses c "
        "JOIN enrollments e ON c.id = e.course_id WHERE e.user_id = ?",
        (user["id"],),
    ).fetchall()

    return render_template("profile.html", profile_user=user, enrollments=enrollments, db_error=None)


# ---------- Change email ----------------------------------------------------
@app.route("/change_email", methods=["GET", "POST"])
def change_email():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    success = None
    error = None

    if request.method == "POST":
        # FIX 0f: CSRF token verified — forged cross-origin POST returns 403
        verify_csrf()

        new_email = request.form.get("email", "").strip()
        if new_email:
            db.execute(
                "UPDATE users SET email=? WHERE id=?",
                (new_email, session["user_id"]),
            )
            db.commit()
            success = f"Email updated to {new_email}."
        else:
            error = "Email cannot be empty."

    user = db.execute(
        "SELECT * FROM users WHERE id=?", (session["user_id"],)
    ).fetchone()
    return render_template("change_email.html", user=user, success=success, error=error)


# ---------- Admin user list -------------------------------------------------
@app.route("/admin/users")
def admin_users():
    if session.get("role") != "admin":
        abort(403)
    db = get_db()
    users = db.execute("SELECT id, username, role, email FROM users").fetchall()
    return render_template("admin_users.html", users=users)


# ---------- Error handlers --------------------------------------------------
@app.errorhandler(400)
def bad_request(e):
    return render_template("403.html", error_code=400, error_msg="Bad Request — invalid input rejected."), 400


@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html", error_code=403,
        error_msg="CSRF token missing or invalid — request blocked."), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("403.html", error_code=404, error_msg="Page not found."), 404


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, port=5002)
