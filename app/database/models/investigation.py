from app.database.db import db
import json


class Investigation(db.Model):

    __tablename__ = "investigations"
    __table_args__ = (
        db.UniqueConstraint("id", "owner_user_id", name="uq_investigation_id_owner"),
        db.Index("ix_investigations_owner_created", "owner_user_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)

    owner_user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )

    target = db.Column(db.String(2048), nullable=False)

    query_type = db.Column(db.String(50), nullable=False)

    risk_score = db.Column(db.Integer, default=0)

    verdict = db.Column(db.String(50))

    analysis_status = db.Column(
        db.String(32),
        nullable=False,
        default="completed",
        server_default="legacy",
    )

    summary = db.Column(db.Text)

    evidence_json = db.Column(db.Text)

    recommendations_json = db.Column(db.Text)

    enrichment_json = db.Column(db.Text)

    data_sources_json = db.Column(db.Text)

    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )

    owner = db.relationship("User", back_populates="investigations")
    activity = db.relationship("ActivityLog", back_populates="investigation", viewonly=True)

    @staticmethod
    def _load_list(value):
        if not value:
            return []
        try:
            result = json.loads(value)
            return result if isinstance(result, list) else []
        except (TypeError, ValueError):
            return []

    @property
    def evidence(self):
        return self._load_list(self.evidence_json)

    @property
    def recommendations(self):
        return self._load_list(self.recommendations_json)

    @property
    def enrichment(self):
        return self._load_list(self.enrichment_json)

    @property
    def data_sources(self):
        return self._load_list(self.data_sources_json)

    def __repr__(self):
        return f"<Investigation {self.id}>"
