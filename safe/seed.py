"""
Seed script for the SAFE version of Campus Portal.
Run once: python seed.py
Wipe and reseed: delete portal.db, then run again.
"""
import sqlite3, os, pathlib

DB = pathlib.Path(__file__).parent / "portal.db"
SCHEMA = pathlib.Path(__file__).parent / "schema.sql"


def seed():
    if DB.exists():
        DB.unlink()

    con = sqlite3.connect(DB)
    con.executescript(SCHEMA.read_text())

    # --- Users ---
    users = [
        ("alice",  "alice123",  "student", "alice@campus.edu"),
        ("bob",    "bob123",    "student", "bob@campus.edu"),
        ("carol",  "carol456",  "student", "carol@campus.edu"),
        ("admin",  "adminpass", "admin",   "admin@campus.edu"),
    ]
    con.executemany(
        "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
        users,
    )

    # --- Courses ---
    courses = [
        ("CS301",  "Data Structures and Algorithms",    "Dr. Sandra Hollis",    3),
        ("CS401",  "Database Systems",                  "Prof. James Mercer",   3),
        ("CS412",  "Computer Networks",                 "Dr. Amara Osei",       3),
        ("CS450",  "Operating Systems",                 "Prof. Nathan Bryce",   4),
        ("MATH310","Linear Algebra for Computing",      "Dr. Elena Vasquez",    3),
        ("SE320",  "Software Engineering Principles",   "Prof. David Ashworth", 3),
        ("CS480",  "Artificial Intelligence Fundamentals","Dr. Priya Nair",     4),
        ("CS490",  "Capstone Project",                  "Dr. Sandra Hollis",    6),
    ]
    con.executemany(
        "INSERT INTO courses (code, title, instructor, credits) VALUES (?, ?, ?, ?)",
        courses,
    )

    # --- Enrollments (alice=1, bob=2, carol=3) ---
    enrollments = [
        (1, 1), (1, 2), (1, 5), (1, 6),   # alice
        (2, 1), (2, 3), (2, 4),            # bob
        (3, 2), (3, 5), (3, 7), (3, 8),   # carol
    ]
    con.executemany("INSERT INTO enrollments VALUES (?, ?)", enrollments)

    # --- Announcements ---
    announcements = [
        (
            "Mid-semester grades now available",
            "Students may review their mid-semester marks via the Registrar's Office portal. "
            "Any discrepancies must be reported within 14 days of publication.",
        ),
        (
            "Campus network maintenance — Saturday 02:00-06:00",
            "The university data centre will undergo scheduled maintenance this Saturday. "
            "Library e-resources and remote VPN access will be unavailable during this window.",
        ),
        (
            "CS301 assignment 3 deadline extended",
            "Due to the public holiday on Friday, the deadline for CS301 Assignment 3 has been "
            "extended to Monday 23:59. No further extensions will be granted.",
        ),
    ]
    con.executemany(
        "INSERT INTO announcements (title, body) VALUES (?, ?)", announcements
    )

    # --- Seed comments (clean) ---
    comments = [
        (1, "alice", "Has anyone started on the CS301 sorting assignment yet?"),
        (2, "bob",   "I finished the quicksort part — the recursion depth tripped me up at first."),
        (3, "carol", "The mid-term review session for MATH310 is on Thursday at 4 pm in Room 214."),
    ]
    con.executemany(
        "INSERT INTO comments (user_id, username, body) VALUES (?, ?, ?)", comments
    )

    con.commit()
    con.close()
    print(f"[seed] Database written to {DB}")


if __name__ == "__main__":
    seed()
