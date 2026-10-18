-- Campus Portal schema  (vulnerable version)
-- Used by both vulnerable and safe versions

CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,          -- plain-text (VULN: no hashing)
    role     TEXT NOT NULL DEFAULT 'student',   -- student | teacher | admin
    email    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS courses (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    code       TEXT NOT NULL,
    title      TEXT NOT NULL,
    instructor TEXT NOT NULL,        -- matches users.username for teacher role
    credits    INTEGER NOT NULL DEFAULT 3
);

CREATE TABLE IF NOT EXISTS enrollments (
    user_id   INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    grade     TEXT    NOT NULL DEFAULT 'N/A',
    PRIMARY KEY (user_id, course_id)
);

CREATE TABLE IF NOT EXISTS comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    username   TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS announcements (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    author     TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
