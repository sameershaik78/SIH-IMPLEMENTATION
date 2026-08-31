from database import db

class SecurityControl(db.Model):
    __tablename__ = 'security_controls'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)  # Network, Endpoint, Identity, Data, Application, Awareness, etc.
    implementation_cost = db.Column(db.Float, nullable=False)  # One-time cost in INR (₹)
    maintenance_cost = db.Column(db.Float, nullable=False)  # Recurring cost in INR (₹)
    effectiveness = db.Column(db.Float, nullable=False)  # 0-100 %
    coverage = db.Column(db.Float, nullable=False)  # 0-100 %
    status = db.Column(db.String(20), default='Inactive')  # Active, Inactive, Proposed
    risk_reduction_factor = db.Column(db.Float, nullable=False)  # 0-100 %
    description = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category,
            'implementation_cost': self.implementation_cost,
            'maintenance_cost': self.maintenance_cost,
            'effectiveness': self.effectiveness,
            'coverage': self.coverage,
            'status': self.status,
            'risk_reduction_factor': self.risk_reduction_factor,
            'description': self.description
        }
