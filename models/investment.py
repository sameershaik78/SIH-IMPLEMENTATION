from database import db
from datetime import datetime

class Investment(db.Model):
    __tablename__ = 'investments'

    id = db.Column(db.Integer, primary_key=True)
    budget = db.Column(db.Float, nullable=False)
    total_cost = db.Column(db.Float, default=0.0)
    expected_risk_reduction = db.Column(db.Float, default=0.0)  # Percentage reduction
    expected_loss_before = db.Column(db.Float, default=0.0)
    expected_loss_after = db.Column(db.Float, default=0.0)
    roi = db.Column(db.Float, default=0.0)  # Percentage ROI
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    recommendations = db.relationship('Recommendation', backref='investment', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'budget': self.budget,
            'total_cost': self.total_cost,
            'expected_risk_reduction': self.expected_risk_reduction,
            'expected_loss_before': self.expected_loss_before,
            'expected_loss_after': self.expected_loss_after,
            'roi': self.roi,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Recommendation(db.Model):
    __tablename__ = 'recommendations'

    id = db.Column(db.Integer, primary_key=True)
    investment_id = db.Column(db.Integer, db.ForeignKey('investments.id'), nullable=False)
    control_id = db.Column(db.Integer, db.ForeignKey('security_controls.id'), nullable=False)
    recommended = db.Column(db.Boolean, default=False)

    # Relationship
    control = db.relationship('SecurityControl', backref='recommendations', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'investment_id': self.investment_id,
            'control_id': self.control_id,
            'control_name': self.control.name if self.control else None,
            'control_cost': (self.control.implementation_cost + self.control.maintenance_cost) if self.control else 0.0,
            'control_effectiveness': self.control.effectiveness if self.control else 0.0,
            'control_reduction': self.control.risk_reduction_factor if self.control else 0.0,
            'recommended': self.recommended
        }
