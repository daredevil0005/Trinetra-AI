from app.database.db import db
from sqlalchemy import text


class User(db.Model):
    __tablename__ = "users"
    __table_args__ = (
        db.CheckConstraint("role IN ('admin', 'user')", name="ck_users_supported_role"),
        db.CheckConstraint("length(username) BETWEEN 3 AND 32", name="ck_users_username_length"),
        db.Index(
            "uq_users_single_legacy_owner",
            "is_legacy_owner",
            unique=True,
            sqlite_where=text("is_legacy_owner = 1"),
            postgresql_where=text("is_legacy_owner"),
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(16), nullable=False, default="user")
    is_active = db.Column(db.Boolean, nullable=False, default=True, server_default=db.true())
    must_change_password = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
    is_legacy_owner = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
    session_version = db.Column(db.Integer, nullable=False, default=1, server_default="1")
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now(), onupdate=db.func.now())
    last_login_at = db.Column(db.DateTime)

    investigations = db.relationship("Investigation", back_populates="owner")
    activity = db.relationship("ActivityLog", back_populates="user")

    @property
    def is_admin(self):
        return self.role == "admin"

    def __repr__(self):
        return f"<User {self.id} {self.username!r}>"


class LoginThrottle(db.Model):
    __tablename__ = "login_throttles"

    bucket_key = db.Column(db.String(64), primary_key=True)
    failures = db.Column(db.Integer, nullable=False, default=0)
    window_started_at = db.Column(db.DateTime, nullable=False)
    blocked_until = db.Column(db.DateTime)


class AdminAuditLog(db.Model):
    __tablename__ = "admin_audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    actor_user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    subject_user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )
    event_type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())

    actor = db.relationship("User", foreign_keys=[actor_user_id])
    subject = db.relationship("User", foreign_keys=[subject_user_id])
