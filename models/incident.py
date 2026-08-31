from database import db
from datetime import datetime

class Incident(db.Model):
    __tablename__ = 'incidents'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # Phishing, Ransomware, Leak, etc.
    impact_cost = db.Column(db.Float, nullable=False)  # Monetary damage in INR (₹)
    incident_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Mitigated')  # Mitigated, Investigating, Active

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'asset_id': self.asset_id,
            'asset_name': self.asset.name if self.asset else None,
            'type': self.type,
            'impact_cost': self.impact_cost,
            'incident_date': self.incident_date.isoformat() if self.incident_date else None,
            'status': self.status
        }
