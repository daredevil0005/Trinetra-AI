import secrets
import unittest

from app import create_app


class ProductionConfigurationTests(unittest.TestCase):
    def config(self, **overrides):
        result = {
            "TESTING": False,
            "TRINETRA_ENV": "production",
            "SECRET_KEY": secrets.token_urlsafe(48),
            "SESSION_COOKIE_SECURE": True,
            "SESSION_COOKIE_HTTPONLY": True,
            "SESSION_COOKIE_SAMESITE": "Lax",
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
        }
        result.update(overrides)
        return result

    def test_production_requires_persistent_strong_secret_and_secure_cookie(self):
        for overrides in (
            {"SECRET_KEY": None},
            {"SECRET_KEY": "short"},
            {"SECRET_KEY": "replace-with-a-long-random-value"},
            {"SECRET_KEY": "a" * 48},
            {"SECRET_KEY": "test-secret-that-is-long-but-still-a-placeholder"},
            {"SESSION_COOKIE_SECURE": False},
            {"SESSION_COOKIE_HTTPONLY": False},
            {"SESSION_COOKIE_SAMESITE": "None"},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(RuntimeError):
                create_app(self.config(**overrides))

    def test_explicit_production_configuration_is_accepted(self):
        app = create_app(self.config())
        self.assertEqual(app.config["TRINETRA_ENV"], "production")
        self.assertTrue(app.config["SESSION_COOKIE_SECURE"])
        self.assertTrue(app.config["SESSION_COOKIE_HTTPONLY"])
        self.assertEqual(app.config["SESSION_COOKIE_SAMESITE"], "Lax")


if __name__ == "__main__":
    unittest.main()
