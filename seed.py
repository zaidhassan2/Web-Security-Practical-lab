"""
Seed script for the VULNERABLE version of Campus Portal.
Run once: python seed.py
Wipe and reseed: delete portal.db, then run again.

Roles
-----
admin     / adminpass   → Administrator
drhollis  / teacher123  → Teacher (CS301, CS490)
drmercer  / teacher123  → Teacher (CS401)
alice     / alice123    → Student
bob       / bob123      → Student
carol     / carol456    → Student
"""
import sqlite3, pathlib

DB = pathlib.Path(__file__).parent / "portal.db"
SCHEMA = pathlib.Path(__file__).parent / "schema.sql"


def seed():
    if DB.exists():
        DB.unlink()

    con = sqlite3.connect(DB)
    con.executescript(SCHEMA.read_text())

    # ------------------------------------------------------------------ Users
    # Passwords stored in PLAIN TEXT — intentional vulnerability
    users = [
        # username       password       role       email
        ("admin",    "adminpass",  "admin",   "admin@campus.edu"),
        ("drhollis", "teacher123", "teacher", "s.hollis@campus.edu"),
        ("drmercer", "teacher123", "teacher", "j.mercer@campus.edu"),
        ("alice",    "alice123",   "student", "alice@campus.edu"),
        ("bob",      "bob123",     "student", "bob@campus.edu"),
        ("carol",    "carol456",   "student", "carol@campus.edu"),
    ]
    con.executemany(
        "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
        users,
    )
    # IDs: admin=1, drhollis=2, drmercer=3, alice=4, bob=5, carol=6

    # ----------------------------------------------------------------- Courses
    # instructor column matches the teacher's username so the teacher dashboard
    # can filter courses with: WHERE instructor = session['username']
    courses = [
        # code      title                                    instructor   credits
        ("CS301",   "Data Structures and Algorithms",       "drhollis",  3),
        ("CS401",   "Database Systems",                     "drmercer",  3),
        ("CS412",   "Computer Networks",                    "drmercer",  3),
        ("CS450",   "Operating Systems",                    "drhollis",  4),
        ("MATH310", "Linear Algebra for Computing",         "drmercer",  3),
        ("SE320",   "Software Engineering Principles",      "drhollis",  3),
        ("CS480",   "Artificial Intelligence Fundamentals", "drhollis",  4),
        ("CS490",   "Capstone Project",                     "drhollis",  6),
    ]
    con.executemany(
        "INSERT INTO courses (code, title, instructor, credits) VALUES (?, ?, ?, ?)",
        courses,
    )
    # IDs: CS301=1, CS401=2, CS412=3, CS450=4, MATH310=5, SE320=6, CS480=7, CS490=8

    # --------------------------------------------------------------- Enrollments
    # (user_id, course_id, grade)
    enrollments = [
        # Alice (4)
        (4, 1, "A"),   (4, 2, "B+"),  (4, 5, "A-"),  (4, 6, "B"),
        # Bob (5)
        (5, 1, "B"),   (5, 3, "A-"),  (5, 4, "C+"),
        # Carol (6)
        (6, 2, "A+"),  (6, 5, "B-"),  (6, 7, "A"),   (6, 8, "N/A"),
    ]
    con.executemany("INSERT INTO enrollments VALUES (?, ?, ?)", enrollments)

    # ----------------------------------------------------------- Announcements
    announcements = [
        (
            "Mid-semester grades now available",
            "Students may review their mid-semester marks via the Registrar's Office portal. "
            "Any discrepancies must be reported within 14 days of publication.",
            "admin",
        ),
        (
            "Campus network maintenance — Saturday 02:00-06:00",
            "The university data centre will undergo scheduled maintenance this Saturday. "
            "Library e-resources and remote VPN access will be unavailable during this window.",
            "admin",
        ),
        (
            "CS301 Assignment 3 deadline extended",
            "Due to the public holiday on Friday, the deadline for CS301 Assignment 3 has been "
            "extended to Monday 23:59. No further extensions will be granted.",
            "drhollis",
        ),
        (
            "CS401 Lab session moved to Room 204",
            "This week's database lab has been relocated to the new computing lab in Room 204. "
            "Please bring your laptops. Queries from last week's homework will be reviewed.",
            "drmercer",
        ),
    ]
    con.executemany(
        "INSERT INTO announcements (title, body, author) VALUES (?, ?, ?)",
        announcements,
    )

    # ------------------------------------------------------------- Comments
    comments = [
        (4, "alice", "Has anyone started on the CS301 sorting assignment yet?"),
        (5, "bob",   "I finished the quicksort part — the recursion depth tripped me up at first."),
        (6, "carol", "The mid-term review session for MATH310 is on Thursday at 4 pm in Room 214."),
    ]
    con.executemany(
        "INSERT INTO comments (user_id, username, body) VALUES (?, ?, ?)",
        comments,
    )

    con.commit()
    con.close()
    print(f"[seed] Database written to {DB}")
    print()
    print("Login credentials:")
    print("  admin    / adminpass   (Administrator)")
    print("  drhollis / teacher123  (Teacher)")
    print("  drmercer / teacher123  (Teacher)")
    print("  alice    / alice123    (Student)")
    print("  bob      / bob123      (Student)")
    print("  carol    / carol456    (Student)")


if __name__ == "__main__":
    seed()
