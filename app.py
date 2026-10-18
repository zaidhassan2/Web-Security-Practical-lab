"""
Campus Portal — VULNERABLE version  (port 5001)
================================================
Intentionally contains multiple web-security vulnerabilities for
educational demonstration.  Every vulnerability site is annotated with
a # VULN comment.  Do NOT deploy outside localhost.

Roles
-----
admin    — full access: user list, post/delete announcements, delete any comment
teacher  — teacher dashboard: own courses, enrolled students + grades, post announcements
student  — student dashboard: own courses, comment wall, search
"""
import pathlib, sqlite3
from flask import (
    Flask, g, render_template, request, redirect,
    url_for, session, abort, flash
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
BASE         = pathlib.Path(__file__).parent
TEMPLATE_DIR = BASE / "templates"
STATIC_DIR   = BASE / "static"

app = Flask(__name__, template_folder=str(TEMPLATE_DIR), static_folder=str(STATIC_DIR))

# VULN 0: Hardcoded secret key — session cookies are forgeable if key leaks
app.secret_key = "super-secret-hardcoded-key-do-not-use"

# Ports do not isolate cookies: keep the two lab sessions separate.
app.config["SESSION_COOKIE_NAME"] = "vulnerable_session"
# localhost:8080 and localhost:5001 are cross-origin but same-site.
# SameSite does not block this lab's CSRF demo; a CSRF token is needed.
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True   # fine, but no Secure flag (not HTTPS)

# No security headers (CSP, X-Frame-Options, etc.) — see safe/app.py for contrast

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
# Context processor — inject user into every template
# ---------------------------------------------------------------------------
@app.context_processor
def inject_user():
    uid  = session.get("user_id")
    user = None
    if uid:
        db   = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return {"current_user": user, "version": "VULNERABLE"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def login_required(fn):
    """Minimal decorator — no functools.wraps intentionally to keep code short."""
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


def role_required(role):
    def decorator(fn):
        def wrapper(*args, **kwargs):
            if session.get("role") != role:
                abort(403)
            return fn(*args, **kwargs)
        wrapper.__name__ = fn.__name__
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Auth — Login / Logout
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()

        # VULN 1a: SQL Injection — string-concatenated query; no parameterization
        # Payload: username = ' OR '1'='1' --   password = anything
        query = (
            f"SELECT id, username, role FROM users "
            f"WHERE username='{username}' AND password='{password}'"
        )
        try:
            row = db.execute(query).fetchone()
        except sqlite3.OperationalError as e:
            # VULN 1a-err: raw DB error echoed to the user — reveals schema
            error = f"Database error: {e}"
            return render_template("login.html", error=error)

        if row:
            session.clear()
            session["user_id"]  = row["id"]
            session["username"] = row["username"]
            session["role"]     = row["role"]
            # Route to role-specific dashboard
            if row["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            elif row["role"] == "teacher":
                return redirect(url_for("teacher_dashboard"))
            else:
                return redirect(url_for("student_dashboard"))
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Generic /dashboard — redirect by role (keeps old links working)
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    role = session.get("role", "student")
    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    elif role == "teacher":
        return redirect(url_for("teacher_dashboard"))
    return redirect(url_for("student_dashboard"))


# ===========================================================================
# STUDENT DASHBOARD
# ===========================================================================
@app.route("/student/dashboard", methods=["GET", "POST"])
@login_required
def student_dashboard():
    if session.get("role") not in ("student",):
        # VULN: teacher/admin can also visit student dashboard — IDOR / broken
        # access control is intentional for demonstration purposes
        pass   # allow — intentionally weak

    db      = get_db()
    error   = None
    success = None

    if request.method == "POST":
        body = request.form.get("body", "").strip()
        # VULN 0c: No CSRF token check — any cross-origin POST succeeds
        if body:
            # VULN 1b: Stored XSS — comment saved raw, rendered with |safe
            db.execute(
                "INSERT INTO comments (user_id, username, body) VALUES (?, ?, ?)",
                (session["user_id"], session["username"], body),
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
        "SELECT c.code, c.title, c.instructor, e.grade FROM courses c "
        "JOIN enrollments e ON c.id = e.course_id "
        "WHERE e.user_id = ?",
        (session["user_id"],),
    ).fetchall()

    return render_template(
        "student_dashboard.html",
        announcements=announcements,
        comments=comments,
        my_courses=my_courses,
        error=error,
        success=success,
    )


# ===========================================================================
# TEACHER DASHBOARD  &  TEACHER ROUTES
# ===========================================================================
@app.route("/teacher/dashboard")
@login_required
def teacher_dashboard():
    if session.get("role") != "teacher":
        abort(403)

    db       = get_db()
    username = session["username"]

    # Courses taught by this teacher
    my_courses = db.execute(
        "SELECT * FROM courses WHERE instructor = ?", (username,)
    ).fetchall()

    # Students enrolled in teacher's courses with grades
    # VULN: username comes from session, but session role check is only role=='teacher'
    # A student who can forge their session role can reach this route
    enrolled_students = db.execute(
        """
        SELECT u.id, u.username, u.email, c.code, c.title, e.grade
        FROM   enrollments e
        JOIN   users   u ON u.id   = e.user_id
        JOIN   courses c ON c.id   = e.course_id
        WHERE  c.instructor = ?
        ORDER  BY c.code, u.username
        """,
        (username,),
    ).fetchall()

    recent_announcements = db.execute(
        "SELECT * FROM announcements WHERE author = ? ORDER BY created_at DESC LIMIT 5",
        (username,),
    ).fetchall()

    return render_template(
        "teacher_dashboard.html",
        my_courses=my_courses,
        enrolled_students=enrolled_students,
        recent_announcements=recent_announcements,
    )


@app.route("/teacher/post_announcement", methods=["GET", "POST"])
@login_required
def teacher_post_announcement():
    if session.get("role") != "teacher":
        abort(403)

    db      = get_db()
    success = None
    error   = None

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body  = request.form.get("body",  "").strip()
        # VULN 0c: No CSRF token — cross-origin POST works
        if title and body:
            # VULN 1b: body stored raw — stored XSS possible
            db.execute(
                "INSERT INTO announcements (title, body, author) VALUES (?, ?, ?)",
                (title, body, session["username"]),
            )
            db.commit()
            success = "Announcement posted."
        else:
            error = "Title and body are required."

    announcements = db.execute(
        "SELECT * FROM announcements WHERE author = ? ORDER BY created_at DESC",
        (session["username"],),
    ).fetchall()

    return render_template(
        "teacher_post_announcement.html",
        announcements=announcements,
        success=success,
        error=error,
    )


@app.route("/teacher/grades", methods=["GET", "POST"])
@login_required
def teacher_grades():
    if session.get("role") != "teacher":
        abort(403)

    db      = get_db()
    success = None
    error   = None

    if request.method == "POST":
        enrollment_user_id  = request.form.get("user_id",   "")
        enrollment_course_id = request.form.get("course_id", "")
        new_grade            = request.form.get("grade",     "").strip()
        # VULN 0c: No CSRF token
        # VULN: no verification that this course belongs to the teacher —
        #        a teacher can update grades for ANY course (broken access control)
        if enrollment_user_id and enrollment_course_id and new_grade:
            db.execute(
                "UPDATE enrollments SET grade=? WHERE user_id=? AND course_id=?",
                (new_grade, enrollment_user_id, enrollment_course_id),
            )
            db.commit()
            success = f"Grade updated to '{new_grade}'."
        else:
            error = "All fields are required."

    username = session["username"]
    enrolled_students = db.execute(
        """
        SELECT u.id AS user_id, u.username, c.id AS course_id,
               c.code, c.title, e.grade
        FROM   enrollments e
        JOIN   users   u ON u.id = e.user_id
        JOIN   courses c ON c.id = e.course_id
        WHERE  c.instructor = ?
        ORDER  BY c.code, u.username
        """,
        (username,),
    ).fetchall()

    return render_template(
        "teacher_grades.html",
        enrolled_students=enrolled_students,
        success=success,
        error=error,
    )


# ===========================================================================
# ADMIN DASHBOARD  &  ADMIN ROUTES
# ===========================================================================
@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    if session.get("role") != "admin":
        abort(403)

    db    = get_db()
    stats = {
        "total_users":   db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_courses": db.execute("SELECT COUNT(*) FROM courses").fetchone()[0],
        "total_comments":db.execute("SELECT COUNT(*) FROM comments").fetchone()[0],
        "total_ann":     db.execute("SELECT COUNT(*) FROM announcements").fetchone()[0],
    }
    recent_users = db.execute(
        "SELECT id, username, role, email FROM users ORDER BY id DESC LIMIT 6"
    ).fetchall()
    recent_comments = db.execute(
        "SELECT * FROM comments ORDER BY created_at DESC LIMIT 5"
    ).fetchall()

    return render_template(
        "admin_dashboard.html",
        stats=stats,
        recent_users=recent_users,
        recent_comments=recent_comments,
    )


@app.route("/admin/users")
@login_required
def admin_users():
    if session.get("role") != "admin":
        abort(403)
    db    = get_db()
    users = db.execute("SELECT id, username, role, email FROM users").fetchall()
    return render_template("admin_users.html", users=users)


@app.route("/admin/announcements", methods=["GET", "POST"])
@login_required
def admin_announcements():
    if session.get("role") != "admin":
        abort(403)

    db      = get_db()
    success = None
    error   = None

    if request.method == "POST":
        action = request.form.get("action", "post")

        if action == "delete":
            ann_id = request.form.get("ann_id", "")
            # VULN 0c: No CSRF token — forged cross-origin DELETE works
            if ann_id:
                db.execute("DELETE FROM announcements WHERE id=?", (ann_id,))
                db.commit()
                success = "Announcement deleted."

        else:  # post
            title = request.form.get("title", "").strip()
            body  = request.form.get("body",  "").strip()
            # VULN 0c: No CSRF token
            if title and body:
                # VULN 1b: stored XSS — body not sanitized
                db.execute(
                    "INSERT INTO announcements (title, body, author) VALUES (?, ?, ?)",
                    (title, body, session["username"]),
                )
                db.commit()
                success = "Announcement posted."
            else:
                error = "Title and body are required."

    announcements = db.execute(
        "SELECT * FROM announcements ORDER BY created_at DESC"
    ).fetchall()
    return render_template(
        "admin_announcements.html",
        announcements=announcements,
        success=success,
        error=error,
    )


@app.route("/admin/delete_comment/<int:comment_id>", methods=["POST"])
@login_required
def admin_delete_comment(comment_id):
    if session.get("role") != "admin":
        abort(403)
    # VULN 0c: No CSRF token — forged cross-origin POST deletes any comment
    db = get_db()
    db.execute("DELETE FROM comments WHERE id=?", (comment_id,))
    db.commit()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/promote", methods=["POST"])
@login_required
def admin_promote():
    """Change a user's role — admin only.  VULN: No CSRF token."""
    if session.get("role") != "admin":
        abort(403)
    db      = get_db()
    uid     = request.form.get("uid", "")
    new_role = request.form.get("role", "student")
    # VULN 0c: No CSRF token — cross-origin role escalation attack possible
    if uid:
        db.execute("UPDATE users SET role=? WHERE id=?", (new_role, uid))
        db.commit()
    return redirect(url_for("admin_users"))


# ===========================================================================
# SHARED ROUTES (all roles)
# ===========================================================================

# ---------- Course search ---------------------------------------------------
@app.route("/search")
@login_required
def search():
    term     = request.args.get("q", "")
    db       = get_db()
    courses  = []
    db_error = None

    if term:
        # VULN 2a: SQL Injection in LIKE — string-concatenated query
        # Payload: ' UNION SELECT 1,username,password,email,4 FROM users --
        query = f"SELECT * FROM courses WHERE title LIKE '%{term}%' OR code LIKE '%{term}%'"
        try:
            courses = db.execute(query).fetchall()
        except sqlite3.OperationalError as e:
            # VULN 2b: raw DB error echoed to user
            db_error = f"Database error: {e}"

    # VULN 1c: Reflected XSS — term echoed with |safe in the template
    return render_template("search.html", courses=courses, term=term, db_error=db_error)


# ---------- Profile ---------------------------------------------------------
@app.route("/profile")
@app.route("/profile/<uid>")
@login_required
def profile(uid=None):
    db = get_db()
    if uid is None:
        uid = session["user_id"]

    # VULN 2c: SQL Injection via UNION — uid not coerced to int
    # Payload: 0 UNION SELECT 1,username,password,role,email FROM users LIMIT 1 OFFSET 0
    query = f"SELECT * FROM users WHERE id={uid}"
    try:
        user = db.execute(query).fetchone()
    except sqlite3.OperationalError as e:
        return render_template("profile.html", profile_user=None, db_error=str(e))

    if not user:
        abort(404)

    enrollments = db.execute(
        "SELECT c.code, c.title, c.instructor, e.grade FROM courses c "
        "JOIN enrollments e ON c.id = e.course_id WHERE e.user_id = ?",
        (user["id"],),
    ).fetchall()

    return render_template("profile.html", profile_user=user, enrollments=enrollments, db_error=None)


# ---------- Change email ----------------------------------------------------
@app.route("/change_email", methods=["GET", "POST"])
@login_required
def change_email():
    db      = get_db()
    success = None
    error   = None

    if request.method == "POST":
        new_email = request.form.get("email", "").strip()
        # VULN 0d: No CSRF token — email changed via forged cross-origin POST
        if new_email:
            db.execute(
                "UPDATE users SET email=? WHERE id=?",
                (new_email, session["user_id"]),
            )
            db.commit()
            success = f"Email updated to {new_email}."
        else:
            error = "Email cannot be empty."

    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return render_template("change_email.html", user=user, success=success, error=error)


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template("404.html", error_code=403,
                           error_msg="Forbidden — you don't have permission to view this page."), 403


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, port=5001)
