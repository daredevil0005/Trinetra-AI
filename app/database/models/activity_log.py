from app.database.db import db


class ActivityLog(db.Model):
    __tablename__ = "activity_logs"
    __table_args__ = (
        db.ForeignKeyConstraint(
            ["investigation_id", "user_id"],
            ["investigations.id", "investigations.owner_user_id"],
            ondelete="RESTRICT",
            name="fk_activity_investigation_owner",
        ),
        db.Index("ix_activity_logs_user_created", "user_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    investigation_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now(), nullable=False)

    investigation = db.relationship("Investigation", back_populates="activity", viewonly=True)
    user = db.relationship("User", back_populates="activity")

    def __repr__(self):
        return f"<ActivityLog {self.event_type} {self.id}>"
