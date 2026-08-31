from database import db
from datetime import datetime

class Threat(db.Model):
    __tablename__ = 'threats'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # Ransomware, Phishing, Malware, DDoS, etc.
    severity = db.Column(db.String(20), nullable=False)  # Low, Medium, High, Critical
    frequency = db.Column(db.Integer, default=1)  # 1-5
    likelihood = db.Column(db.Integer, default=1)  # 1-5
    attack_vector = db.Column(db.String(100))
    threat_actor = db.Column(db.String(100))
    affected_asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=True)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='Active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type,
            'severity': self.severity,
            'frequency': self.frequency,
            'likelihood': self.likelihood,
            'attack_vector': self.attack_vector,
            'threat_actor': self.threat_actor,
            'affected_asset_id': self.affected_asset_id,
            'affected_asset_name': self.asset.name if self.asset else "All Assets",
            'description': self.description,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
