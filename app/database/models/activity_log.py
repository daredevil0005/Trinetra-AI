from app.database.db import db


class ActivityLog(db.Model):
    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    investigation_id = db.Column(
        db.Integer,
        db.ForeignKey("investigations.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at = db.Column(db.DateTime, server_default=db.func.now(), nullable=False)

    investigation = db.relationship("Investigation", back_populates="activity")

    def __repr__(self):
        return f"<ActivityLog {self.event_type} {self.id}>"
