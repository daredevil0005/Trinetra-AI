import hmac
import secrets

from flask import abort, request, session


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def init_csrf(app):
    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": csrf_token}

    @app.before_request
    def protect_state_changing_requests():
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return None
        supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        expected = session.get("_csrf_token", "")
        if not supplied or not expected or not hmac.compare_digest(supplied, expected):
            abort(400, description="The form expired or its security token was invalid. Reload the page and try again.")
        return None
