from database import db
from datetime import datetime

class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(50), nullable=False)  # VULNERABILITY, THREAT, RISK_INCREASE, CONTROL_WEAKNESS, BUDGET_OPPORTUNITY
    severity = db.Column(db.String(20), nullable=False)  # INFO, WARNING, HIGH, CRITICAL
    title = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=True)
    risk_score = db.Column(db.Float, nullable=True)
    status = db.Column(db.String(20), default='Unread')  # Unread, Read
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'title': self.title,
            'message': self.message,
            'asset_id': self.asset_id,
            'asset_name': self.asset.name if self.asset else "General",
            'risk_score': self.risk_score,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
