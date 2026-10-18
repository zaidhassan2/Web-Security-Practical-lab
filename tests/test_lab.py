"""Exercise the assignment against temporary seeded databases, never portal.db.
Run: python3 -m unittest discover -s tests -v
"""
import contextlib
import importlib.util
import io
from pathlib import Path
import sqlite3
import tempfile
import unittest
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LabTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.modules = {}
        self.clients = {}
        for version in ('vulnerable', 'safe'):
            seed = load(version + '_seed', ROOT / version / 'seed.py')
            seed.DB = Path(self.tmp.name) / (version + '.db')
            with contextlib.redirect_stdout(io.StringIO()):
                seed.seed()
            module = load(version + '_app', ROOT / version / 'app.py')
            module.DB_PATH = seed.DB
            module.app.config['TESTING'] = True
            self.modules[version] = module
            self.clients[version] = module.app.test_client()

    def login(self, version, user='alice', follow=True):
        password = {'alice': 'alice123', 'bob': 'bob123', 'admin': 'adminpass'}[user]
        return self.clients[version].post('/login', data={
            'username': user, 'password': password,
        }, follow_redirects=follow)

    def value(self, version, sql):
        with contextlib.closing(sqlite3.connect(self.modules[version].DB_PATH)) as con:
            return con.execute(sql).fetchone()[0]

    def test_reflected_xss_and_url_plus(self):
        payload = "<script>alert('Cookie: '+document.cookie)</script>"
        for version in self.clients:
            self.login(version)
            c = self.clients[version]
            r = c.get('/search', query_string={'q': payload})
            self.assertEqual(r.status_code, 200)
            if version == 'vulnerable':
                self.assertIn(payload, r.text)
                self.assertIn('Database error:', r.text)
                broken = c.get('/search?q=' + payload).text
                self.assertIn("alert('Cookie: ' document.cookie)", broken)
            else:
                self.assertNotIn(payload, r.text)
                self.assertIn('&lt;script&gt;', r.text)
                self.assertNotIn('Database error:', r.text)

    def test_stored_xss_persists_and_safe_escapes_once(self):
        payload = "<script>alert('stored-xss')</script>"
        for version, route in [('vulnerable', '/student/dashboard'), ('safe', '/dashboard')]:
            self.login(version)
            c = self.clients[version]
            data = {'body': payload}
            if version == 'safe':
                with c.session_transaction() as sess:
                    data['csrf_token'] = sess['csrf_token']
            self.assertEqual(c.post(route, data=data).status_code, 200)
            self.login(version, 'bob')
            text = c.get(route).text
            if version == 'vulnerable':
                self.assertIn(payload, text)
            else:
                self.assertNotIn(payload, text)
                self.assertIn('&lt;script&gt;', text)
                self.assertNotIn('&amp;lt;script', text)

    def test_csrf_email_and_comment(self):
        for version, route in [('vulnerable', '/student/dashboard'), ('safe', '/dashboard')]:
            self.login(version)
            c = self.clients[version]
            before = self.value(version, 'SELECT COUNT(*) FROM comments')
            response = c.post('/change_email', data={'email': 'attacker@evil.tld'},
                              headers={'Origin': 'http://localhost:8080'})
            comment = c.post(route, data={'body': 'forged-comment'},
                             headers={'Origin': 'http://localhost:8080'})
            email = self.value(version, "SELECT email FROM users WHERE username='alice'")
            after = self.value(version, 'SELECT COUNT(*) FROM comments')
            self.assertEqual(response.status_code, 200 if version == 'vulnerable' else 403)
            self.assertEqual(comment.status_code, 200 if version == 'vulnerable' else 403)
            self.assertEqual(email, 'attacker@evil.tld' if version == 'vulnerable' else 'alice@campus.edu')
            self.assertEqual(after, before + (version == 'vulnerable'))

    def test_safe_csrf_rejects_empty_session_token_after_login(self):
        self.login('safe', follow=False)
        r = self.clients['safe'].post('/change_email', data={'email': 'attacker@evil.tld'})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.value('safe', "SELECT email FROM users WHERE username='alice'"), 'alice@campus.edu')

    def test_safe_csrf_rejects_wrong_token_and_allows_correct_token(self):
        self.login('safe')
        c = self.clients['safe']
        r = c.post('/change_email', data={'email': 'changed@example.test', 'csrf_token': 'wrong'})
        self.assertEqual(r.status_code, 403)
        with c.session_transaction() as sess:
            token = sess['csrf_token']
        r = c.post('/change_email', data={'email': 'changed@example.test', 'csrf_token': token})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.value('safe', "SELECT email FROM users WHERE username='alice'"), 'changed@example.test')

    def test_cookies_have_distinct_names_and_remain_httponly(self):
        names = []
        for version in self.clients:
            r = self.login(version, follow=False)
            name = self.modules[version].app.config['SESSION_COOKIE_NAME']
            names.append(name)
            self.assertIn(name + '=', r.headers['Set-Cookie'])
            self.assertIn('HttpOnly', r.headers['Set-Cookie'])
        self.assertNotEqual(*names)

    def test_sqli_login_search_and_profile(self):
        for version, c in self.clients.items():
            r = c.post('/login', data={'username': "' OR '1'='1' --", 'password': 'x'})
            self.assertEqual(r.status_code, 302 if version == 'vulnerable' else 200)
            if version == 'safe':
                self.assertIn('Invalid username or password', r.text)
            self.login(version, 'admin')
            r = c.get('/search', query_string={'q': "' UNION SELECT 1,username,password,email,4 FROM users --"})
            self.assertEqual('adminpass' in r.text, version == 'vulnerable')
            r = c.get('/profile/' + quote("0 UNION SELECT id,username,email,role,password FROM users WHERE role='admin'", safe=''))
            self.assertEqual(r.status_code, 200 if version == 'vulnerable' else 400)
            if version == 'vulnerable':
                self.assertIn('adminpass', r.text)
            for condition, expected in [('1=1', True), ('1=2', False)]:
                r = c.get('/search', query_string={'q': "zzznomatch' OR " + condition + ' --'})
                self.assertEqual('id="courses-grid"' in r.text, expected and version == 'vulnerable')


if __name__ == '__main__':
    unittest.main()
