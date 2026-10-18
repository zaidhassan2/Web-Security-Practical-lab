# Campus Portal — Web Security Lab

A full-stack student portal web application built as a controlled educational lab.
The repository contains two parallel versions of the same application: a **Vulnerable**
version in which four classes of web attack work end-to-end, and a **Safe** version in
which every one of those vulnerabilities has been hardened.  Both versions are visually
identical except for a colour-coded version badge visible on every page.

---

## Stack

| Layer     | Technology                                               |
|-----------|----------------------------------------------------------|
| Backend   | Python 3.11+, Flask 3.x                                  |
| Database  | SQLite (one `portal.db` per version, seeded by `seed.py`)|
| Templating| Jinja2 (bundled with Flask)                              |
| Frontend  | Hand-written CSS, vanilla JavaScript — no build step     |
| Auth      | Flask signed-cookie sessions (no external library)       |
| SQL       | Raw `sqlite3` — no ORM, so injection surfaces are visible|

---

## Repository Tree

```
student-portal/
├── README.md
├── GUIDE.md
├── requirements.txt
├── vulnerable/
│   ├── app.py          # Flask app — intentionally vulnerable
│   ├── schema.sql
│   ├── seed.py
│   ├── static/
│   │   ├── style.css   # Red VULNERABLE badge
│   │   └── app.js      # innerHTML — DOM XSS surface
│   └── templates/
│       ├── base.html
│       ├── login.html
│       ├── dashboard.html
│       ├── search.html
│       ├── profile.html
│       ├── change_email.html
│       ├── admin_users.html
│       └── 404.html
├── safe/
│   ├── app.py          # Flask app — hardened
│   ├── schema.sql
│   ├── seed.py
│   ├── static/
│   │   ├── style.css   # Green SAFE badge
│   │   └── app.js      # textContent — DOM XSS blocked
│   └── templates/
│       ├── base.html
│       ├── login.html
│       ├── dashboard.html
│       ├── search.html
│       ├── profile.html
│       ├── change_email.html
│       ├── admin_users.html
│       └── 403.html
└── payloads/
    ├── xss_reflected.txt
    ├── xss_stored.txt
    ├── xss_dom.txt
    ├── csrf.html
    ├── csrf_safe.html
    └── sqli.txt
```

---

## Port Map

| Version    | Port  | URL                    |
|------------|-------|------------------------|
| Vulnerable | 5001  | http://localhost:5001  |
| Safe       | 5002  | http://localhost:5002  |

---

## Seed Users

| Username | Password  | Role    |
|----------|-----------|---------|
| alice    | alice123  | student |
| bob      | bob123    | student |
| carol    | carol456  | student |
| drhollis | teacher123 | teacher (vulnerable only) |
| drmercer | teacher123 | teacher (vulnerable only) |
| admin    | adminpass | admin   |

---

## How to Run

```bash
# 1. Install dependencies (once)
pip install -r requirements.txt

# 2. Terminal A — vulnerable version
cd vulnerable
python seed.py          # creates vulnerable/portal.db
python app.py           # starts on http://localhost:5001

# 3. Terminal B — safe version
cd safe
python seed.py          # creates safe/portal.db
python app.py           # starts on http://localhost:5002
```

---

## Implemented Vulnerabilities and Fixes

| # | Class | Vulnerable code location | Safe code fix |
|---|-------|--------------------------|---------------|
| 1a | SQL Injection — Login bypass | `vulnerable/app.py` `login()` — f-string query | `safe/app.py` `login()` — parameterized `?` |
| 1b | Stored XSS — Comment feed | `vulnerable/templates/dashboard.html` `\|safe` filter | Jinja autoescape at render time; no `\|safe` in template |
| 1c | Reflected XSS — Search term | `vulnerable/templates/search.html` `term \| safe` | `safe/templates/search.html` — `term` rendered with Jinja autoescape |
| 1d | DOM XSS — Welcome banner | `vulnerable/static/app.js` `innerHTML` with `location.hash` | `safe/static/app.js` `textContent` |
| 2a | SQL Injection — Search LIKE | `vulnerable/app.py` `search()` — f-string LIKE query | `safe/app.py` `search()` — parameterized LIKE with `?` |
| 2b | Error leak — Search | `vulnerable/app.py` `except` block echoes `sqlite3.OperationalError` | `safe/app.py` — errors logged server-side only |
| 2c | SQL Injection — Profile UNION | `vulnerable/app.py` `profile()` — `f"WHERE id={uid}"` | `safe/app.py` `profile()` — `int(uid)` coercion + parameterized query |
| 3a | CSRF — Change email | `vulnerable/app.py` `change_email()` — no token check | `safe/app.py` — `verify_csrf()` with `secrets.compare_digest` |
| 3b | CSRF — Post comment | `vulnerable/templates/dashboard.html` — no token in form | `safe/templates/dashboard.html` — `csrf_token` hidden field |

---

## Attack Walkthrough

Start with [XSS_ONWARDS.md](XSS_ONWARDS.md) for reviewed XSS/CSRF steps.
See [GUIDE.md](GUIDE.md) for a full step-by-step lab manual including exact URLs,
form inputs, expected outputs, and a screenshot checklist.
