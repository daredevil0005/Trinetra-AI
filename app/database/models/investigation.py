from app.database.db import db


class Investigation(db.Model):

    __tablename__ = "investigations"

    id = db.Column(db.Integer, primary_key=True)

    target = db.Column(db.String(255), nullable=False)

    query_type = db.Column(db.String(50), nullable=False)

    risk_score = db.Column(db.Integer, default=0)

    verdict = db.Column(db.String(50))

    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )

    def __repr__(self):
        return f"<Investigation {self.query}>"