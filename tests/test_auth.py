"""
Authentication tests.  Run from the project root:

    python -m unittest tests.test_auth -v

Uses a throw-away SQLite database, so MySQL is not needed and your real
data is never touched.
"""

import os
import re
import sys
import tempfile
import unittest

os.environ["DB_BACKEND"] = "sqlite"
os.environ["FLASK_DEBUG"] = "True"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database as db  # noqa: E402

_tmp = tempfile.mkdtemp()
db.SQLITE_PATH = os.path.join(_tmp, "test.db")

import app as app_module  # noqa: E402
from config import Config  # noqa: E402

PW = "Str0ngPass99"


def token_from(html: bytes) -> str:
    m = re.search(rb'name="csrf_token" value="([^"]+)"', html)
    assert m, "no csrf token on page"
    return m.group(1).decode()


class AuthTests(unittest.TestCase):
    def setUp(self):
        # fresh DB for every test
        if os.path.exists(db.SQLITE_PATH):
            os.remove(db.SQLITE_PATH)
        db._backend = None
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    # ---- helpers ----
    def post(self, url, data=None, client=None, page=None, **kw):
        c = client or self.client
        tok = token_from(c.get(page or url).data) if page != "" else ""
        payload = dict(data or {}, csrf_token=tok)
        return c.post(url, data=payload, **kw)

    def make_admin(self):
        self.post("/setup", {"username": "admin", "password": PW, "confirm_password": PW})

    def login(self, username="admin", password=PW, client=None, **kw):
        return self.post("/login", {"username": username, "password": password},
                         client=client, **kw)

    def add_analyst(self, name="alice"):
        self.login()
        self.post("/admin/users/create", {"username": name, "password": PW, "role": "analyst"},
                  page="/admin/users")
        self.client.post("/logout", data={"csrf_token": token_from(self.client.get("/dashboard").data)})

    # ---- tests ----
    def test_protected_routes_redirect_when_anonymous(self):
        self.make_admin()
        for url in ["/dashboard", "/traffic", "/alerts", "/ml-model", "/account", "/admin/users"]:
            r = self.client.get(url)
            self.assertEqual(r.status_code, 302, url)
            self.assertIn("/login", r.headers["Location"], url)

    def test_api_returns_401_not_redirect(self):
        self.make_admin()
        r = self.client.get("/api/dashboard-stats")
        self.assertEqual(r.status_code, 401)

    def test_first_run_goes_to_setup_then_locks(self):
        r = self.client.get("/login")
        self.assertIn("/setup", r.headers["Location"])
        self.make_admin()
        self.assertEqual(db.count_users(), 1)
        r = self.client.get("/setup")                 # setup closes once a user exists
        self.assertIn("/login", r.headers["Location"])

    def test_password_is_hashed(self):
        self.make_admin()
        u = db.get_user_by_username("admin")
        self.assertNotIn(PW, u["password_hash"])
        self.assertTrue(u["password_hash"].startswith(("scrypt:", "pbkdf2:")))

    def test_weak_passwords_rejected(self):
        for bad in ["short1", "allletters", "12345678", "admin1234"]:
            self.post("/setup", {"username": "admin", "password": bad, "confirm_password": bad})
            self.assertEqual(db.count_users(), 0, bad)

    def test_login_success_and_logout(self):
        self.make_admin()
        r = self.login()
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/logout").status_code, 405)   # logout is POST-only
        self.client.post("/logout", data={"csrf_token": token_from(self.client.get("/dashboard").data)})
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_generic_error_for_bad_user_and_bad_password(self):
        self.make_admin()
        a = self.login("admin", "WrongPass1", follow_redirects=True).data
        b = self.login("nobody", "WrongPass1", follow_redirects=True).data
        self.assertIn(b"Invalid username or password.", a)
        self.assertIn(b"Invalid username or password.", b)

    def test_account_lockout(self):
        self.make_admin()
        for _ in range(Config.MAX_FAILED_LOGINS):
            self.login("admin", "WrongPass1")
        r = self.login("admin", PW, follow_redirects=True)      # correct pw, but locked
        self.assertIn(b"temporarily locked", r.data)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_csrf_required(self):
        self.make_admin()
        self.login()
        r = self.client.post("/ml-model/train", data={})          # no token
        self.assertEqual(r.status_code, 302)
        self.client.post("/admin/users/create", data={"username": "evil", "password": PW})
        self.assertIsNone(db.get_user_by_username("evil"))

    def test_open_redirect_blocked(self):
        self.make_admin()
        r = self.post("/login?next=https://evil.example/",
                      {"username": "admin", "password": PW}, page="/login")
        self.assertNotIn("evil.example", r.headers.get("Location", ""))

    def test_next_redirect_allowed_for_local_path(self):
        self.make_admin()
        r = self.post("/login?next=/alerts", {"username": "admin", "password": PW}, page="/login")
        self.assertTrue(r.headers["Location"].endswith("/alerts"))

    def test_analyst_cannot_use_admin_features(self):
        self.make_admin()
        self.add_analyst()
        self.login("alice")
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/admin/users").status_code, 403)
        tok = token_from(self.client.get("/dashboard").data)
        self.assertEqual(self.client.post("/ml-model/train", data={"csrf_token": tok}).status_code, 403)
        self.assertEqual(self.client.post("/admin/users/1/delete", data={"csrf_token": tok}).status_code, 403)

    def test_cannot_remove_last_admin(self):
        self.make_admin()
        self.login()
        admin_id = db.get_user_by_username("admin")["id"]
        self.post(f"/admin/users/{admin_id}/role", {"role": "analyst"}, page="/admin/users")
        self.post(f"/admin/users/{admin_id}/delete", {}, page="/admin/users")
        self.post(f"/admin/users/{admin_id}/active", {}, page="/admin/users")
        u = db.get_user_by_id(admin_id)
        self.assertEqual((u["role"], u["is_active"]), ("admin", 1))

    def test_disabling_user_kills_existing_session(self):
        self.make_admin()
        self.add_analyst()
        alice_client = app_module.app.test_client()
        self.login("alice", client=alice_client)
        self.assertEqual(alice_client.get("/dashboard").status_code, 200)
        self.login()                                              # admin disables alice
        alice_id = db.get_user_by_username("alice")["id"]
        self.post(f"/admin/users/{alice_id}/active", {}, page="/admin/users")
        self.assertEqual(alice_client.get("/dashboard").status_code, 302)

    def test_session_rotates_on_login(self):
        self.make_admin()
        before = token_from(self.client.get("/login").data)
        self.login()
        after = token_from(self.client.get("/dashboard").data)
        self.assertNotEqual(before, after)

    def test_register_closed_by_default(self):
        self.make_admin()
        self.assertFalse(Config.ALLOW_REGISTRATION)
        self.assertEqual(self.client.get("/register").status_code, 302)

    def test_health_hides_details_from_anonymous(self):
        self.make_admin()
        data = self.client.get("/health").get_json()
        self.assertEqual(list(data.keys()), ["status"])

    def test_change_password(self):
        self.make_admin()
        self.login()
        new = "An0therPass42"
        self.post("/account", {"current_password": "bad", "new_password": new, "confirm_password": new})
        self.assertTrue(app_module.auth.check_password_hash(db.get_user_by_username("admin")["password_hash"], PW))
        self.post("/account", {"current_password": PW, "new_password": new, "confirm_password": new})
        self.assertTrue(app_module.auth.check_password_hash(db.get_user_by_username("admin")["password_hash"], new))


if __name__ == "__main__":
    unittest.main()
