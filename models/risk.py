from database import db
from datetime import datetime

class RiskScore(db.Model):
    __tablename__ = 'risk_scores'

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), unique=True, nullable=False)
    likelihood_score = db.Column(db.Float, default=0.0)
    impact_score = db.Column(db.Float, default=0.0)
    raw_score = db.Column(db.Float, default=0.0)
    normalized_score = db.Column(db.Float, default=0.0)  # 0-100
    risk_level = db.Column(db.String(20), default='Low')  # Low, Medium, High, Critical
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'asset_id': self.asset_id,
            'asset_name': self.asset.name if self.asset else None,
            'likelihood_score': self.likelihood_score,
            'impact_score': self.impact_score,
            'raw_score': self.raw_score,
            'normalized_score': self.normalized_score,
            'risk_level': self.risk_level,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class FinancialRisk(db.Model):
    __tablename__ = 'financial_risks'

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), unique=True, nullable=False)
    sle = db.Column(db.Float, default=0.0)  # Single Loss Expectancy in INR
    ale = db.Column(db.Float, default=0.0)  # Annualized Loss Expectancy in INR
    expected_loss = db.Column(db.Float, default=0.0)  # ML-based expected loss in INR
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'asset_id': self.asset_id,
            'asset_name': self.asset.name if self.asset else None,
            'sle': self.sle,
            'ale': self.ale,
            'expected_loss': self.expected_loss,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
