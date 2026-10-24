import re
import unittest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app import create_app
from app.database.db import db
from app.database.migrations import upgrade_database
from app.database.models import ActivityLog, Investigation, User
from app.security.auth import hash_password


class AuthenticationAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "test-only-secret-for-auth-tests-extra",
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "SESSION_COOKIE_SECURE": False,
            "TRINETRA_ENV": "testing",
        })
        with self.app.app_context():
            upgrade_database()
            self.admin = User(username="root", password_hash=hash_password("root password long enough"), role="admin")
            self.alice = User(username="alice", password_hash=hash_password("alice password long enough"), role="user")
            self.bob = User(username="bob", password_hash=hash_password("bob password long enough"), role="user")
            db.session.add_all([self.admin, self.alice, self.bob])
            db.session.commit()
            self.ids = {u.username: u.id for u in (self.admin, self.alice, self.bob)}
        self.admin_client = self.app.test_client()
        self.alice_client = self.app.test_client()
        self.bob_client = self.app.test_client()
        for client, username, password in (
            (self.admin_client, "root", "root password long enough"),
            (self.alice_client, "alice", "alice password long enough"),
            (self.bob_client, "bob", "bob password long enough"),
        ):
            self.assertEqual(self.login(client, username, password).status_code, 302)

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.engine.dispose()

    def token(self, client, path="/login"):
        response = client.get(path)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match, path)
        return match.group(1).decode("ascii")

    def login(self, client, username, password, next_url=None):
        token = self.token(client, "/login")
        data = {"csrf_token": token, "username": username, "password": password}
        if next_url:
            data["next"] = next_url
        return client.post("/login", data=data)

    def make_investigation(self, client, query):
        return client.post("/investigate", data={
            "csrf_token": self.token(client, "/investigate"),
            "query": query,
        })

    def test_successful_login_hashing_logout_and_generic_failure(self):
        client = self.app.test_client()
        response = self.login(client, "root", "wrong password value")
        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Invalid username or password", response.data)
        self.assertNotIn(b"root does not exist", response.data)
        response = self.login(client, " ROOT ", "root password long enough")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        with self.app.app_context():
            user = db.session.get(User, self.ids["root"])
            self.assertNotEqual(user.password_hash, "root password long enough")
            self.assertTrue(user.password_hash.startswith("scrypt:"))
        response = client.post("/logout", data={"csrf_token": self.token(client, "/")})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(client.get("/").status_code, 302)

    def test_inactive_user_cannot_login_and_existing_session_is_revoked(self):
        client = self.app.test_client()
        self.assertEqual(self.login(client, "alice", "alice password long enough").status_code, 302)
        with self.app.app_context():
            user = db.session.get(User, self.ids["alice"])
            user.is_active = False
            user.session_version += 1
            db.session.commit()
        response = client.get("/history")
        self.assertEqual(response.status_code, 302)
        denied = self.login(self.app.test_client(), "alice", "alice password long enough")
        self.assertEqual(denied.status_code, 401)
        self.assertIn(b"Invalid username or password", denied.data)

    def test_login_redirect_is_same_origin_only_and_throttled(self):
        client = self.app.test_client()
        response = self.login(client, "root", "root password long enough", "https://attacker.invalid/steal")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

        throttled = self.app.test_client()
        for _ in range(5):
            failure = self.login(throttled, "unknown-user", "not the password")
            self.assertEqual(failure.status_code, 401)
            self.assertIn(b"Invalid username or password", failure.data)
        response = self.login(throttled, "unknown-user", "not the password")
        self.assertEqual(response.status_code, 429)
        self.assertIn(b"Invalid username or password", response.data)

    def test_password_change_invalidates_all_sessions(self):
        second_session = self.app.test_client()
        self.assertEqual(self.login(second_session, "alice", "alice password long enough").status_code, 302)
        changed = self.alice_client.post("/change-password", data={
            "csrf_token": self.token(self.alice_client, "/change-password"),
            "old_password": "alice password long enough",
            "new_password": "a new password long enough",
            "confirm_password": "a new password long enough",
        })
        self.assertEqual(changed.status_code, 302)
        self.assertEqual(second_session.get("/history").status_code, 302)
        self.assertEqual(self.alice_client.get("/history").status_code, 302)
        login_client = self.app.test_client()
        self.assertEqual(self.login(login_client, "alice", "alice password long enough").status_code, 401)
        self.assertEqual(self.login(login_client, "alice", "a new password long enough").status_code, 302)

    def test_per_user_dashboard_history_reports_and_logs_are_isolated(self):
        self.assertEqual(self.make_investigation(self.alice_client, "alice-only.example").status_code, 200)
        with self.app.app_context():
            alice_record = Investigation.query.filter_by(owner_user_id=self.ids["alice"]).one()
            record_id = alice_record.id

        self.assertEqual(self.bob_client.get(f"/report/{record_id}").status_code, 404)
        self.assertEqual(self.bob_client.get(f"/report/{record_id}/download").status_code, 404)
        self.assertEqual(self.admin_client.get(f"/report/{record_id}").status_code, 404)
        self.assertEqual(self.admin_client.get(f"/report/{record_id}/download").status_code, 404)
        self.assertNotIn(b"alice-only.example", self.bob_client.get("/history").data)
        self.assertNotIn(b"alice-only.example", self.admin_client.get("/history").data)
        self.assertNotIn(b"alice-only.example", self.bob_client.get("/logs").data)
        self.assertNotIn(b"alice-only.example", self.admin_client.get("/logs").data)
        self.assertIn(b"0</strong>", self.bob_client.get("/").data)
        self.assertIn(b"0</strong>", self.admin_client.get("/").data)
        self.assertEqual(self.bob_client.get(f"/report/{record_id}?owner_id={self.ids['alice']}").status_code, 404)

    def test_account_management_is_admin_only_and_does_not_grant_data_access(self):
        self.assertEqual(self.admin_client.get("/users").status_code, 200)
        self.assertEqual(self.alice_client.get("/users").status_code, 403)
        self.assertEqual(self.alice_client.get("/reports").status_code, 404)
        token = self.token(self.alice_client, "/history")
        denied = self.alice_client.post("/users/create", data={
            "csrf_token": token,
            "username": "new-account",
            "role": "admin",
        })
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(self.admin_client.post("/users/1/toggle", data={
            "csrf_token": self.token(self.admin_client, "/users"),
        }).status_code, 400)

    def test_admin_can_create_reset_deactivate_and_reactivate_accounts(self):
        created = self.admin_client.post("/users/create", data={
            "csrf_token": self.token(self.admin_client, "/users"),
            "username": "charlie",
            "role": "user",
        })
        self.assertEqual(created.status_code, 200)
        match = re.search(rb"<code>([^<]+)</code>", created.data)
        self.assertIsNotNone(match)
        temporary_password = match.group(1).decode("ascii")
        with self.app.app_context():
            charlie = User.query.filter_by(username="charlie").one()
            self.assertEqual(charlie.role, "user")
            self.assertTrue(charlie.must_change_password)
            self.assertTrue(charlie.password_hash.startswith("scrypt:"))
            charlie_id = charlie.id

        charlie_client = self.app.test_client()
        self.assertEqual(self.login(charlie_client, "charlie", temporary_password).headers["Location"], "/change-password")

        original_version = None
        with self.app.app_context():
            alice = db.session.get(User, self.ids["alice"])
            original_version = alice.session_version
        reset = self.admin_client.post(f"/users/{self.ids['alice']}/reset-password", data={
            "csrf_token": self.token(self.admin_client, "/users"),
        })
        self.assertEqual(reset.status_code, 200)
        reset_match = re.search(rb"<code>([^<]+)</code>", reset.data)
        self.assertIsNotNone(reset_match)
        reset_password = reset_match.group(1).decode("ascii")
        self.assertEqual(self.alice_client.get("/history").status_code, 302)
        self.assertEqual(self.login(self.app.test_client(), "alice", reset_password).headers["Location"], "/change-password")
        with self.app.app_context():
            alice = db.session.get(User, self.ids["alice"])
            self.assertTrue(alice.must_change_password)
            self.assertGreater(alice.session_version, original_version)

        deactivate = self.admin_client.post(f"/users/{charlie_id}/toggle", data={
            "csrf_token": self.token(self.admin_client, "/users"),
        })
        self.assertEqual(deactivate.status_code, 302)
        self.assertEqual(charlie_client.get("/history").status_code, 302)
        reactivate = self.admin_client.post(f"/users/{charlie_id}/toggle", data={
            "csrf_token": self.token(self.admin_client, "/users"),
        })
        self.assertEqual(reactivate.status_code, 302)
        self.assertEqual(self.login(self.app.test_client(), "charlie", temporary_password).headers["Location"], "/change-password")
        with self.app.app_context():
            events = db.session.execute(text(
                "SELECT event_type FROM admin_audit_logs ORDER BY id"
            )).scalars().all()
            self.assertEqual(events, [
                "user.created", "user.password_reset", "user.deactivated", "user.activated",
            ])

    def test_login_session_cookie_flags_and_closed_registration(self):
        anonymous = self.app.test_client()
        self.token(anonymous, "/login")
        with anonymous.session_transaction() as before_login:
            old_csrf = before_login.get("_csrf_token")
        response = self.login(anonymous, "alice", "alice password long enough")
        cookie_header = response.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie_header)
        self.assertIn("SameSite=Lax", cookie_header)
        self.assertNotIn("Secure", cookie_header)  # test app is explicitly HTTP-only
        with anonymous.session_transaction() as after_login:
            self.assertEqual(after_login.get("_user_id"), str(self.ids["alice"]))
            self.assertNotIn("_csrf_token", after_login)
        self.assertIsNotNone(old_csrf)
        self.assertEqual(anonymous.get("/register").status_code, 404)

    def test_activity_foreign_key_enforces_investigation_owner_match(self):
        self.assertEqual(self.make_investigation(self.alice_client, "owner-bound.example").status_code, 200)
        with self.app.app_context():
            record = Investigation.query.filter_by(owner_user_id=self.ids["alice"]).one()
            db.session.add(ActivityLog(
                user_id=self.ids["bob"],
                investigation_id=record.id,
                event_type="test.mismatch",
                message="not persisted",
            ))
            with self.assertRaises(IntegrityError):
                db.session.commit()
            db.session.rollback()
            violations = db.session.execute(text("PRAGMA foreign_key_check")).all()
            self.assertEqual(violations, [])

    def test_missing_login_csrf_and_password_change_requires_valid_old_password(self):
        anonymous = self.app.test_client()
        response = anonymous.post("/login", data={"username": "root", "password": "value"})
        self.assertEqual(response.status_code, 400)
        response = self.alice_client.post("/change-password", data={
            "csrf_token": self.token(self.alice_client, "/change-password"),
            "old_password": "wrong current password",
            "new_password": "a sufficiently long new password",
            "confirm_password": "a sufficiently long new password",
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"current password is incorrect", response.data)


if __name__ == "__main__":
    unittest.main()

