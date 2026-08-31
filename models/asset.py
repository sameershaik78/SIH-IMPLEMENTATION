from database import db
from datetime import datetime

class Asset(db.Model):
    __tablename__ = 'assets'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # Server, Database, Endpoint, Web Application, Cloud Resource, Network Device, IoT Device
    value = db.Column(db.Float, nullable=False)  # Value in INR (₹)
    criticality = db.Column(db.String(20), nullable=False)  # Low, Medium, High, Critical
    business_importance = db.Column(db.String(100))
    data_sensitivity = db.Column(db.String(100))
    internet_exposure = db.Column(db.Boolean, default=False)
    location = db.Column(db.String(100))
    owner = db.Column(db.String(100))
    status = db.Column(db.String(20), default='Active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='asset', lazy=True, cascade="all, delete-orphan")
    threats = db.relationship('Threat', backref='asset', lazy=True, cascade="all, delete-orphan")
    incidents = db.relationship('Incident', backref='asset', lazy=True, cascade="all, delete-orphan")
    risk_score = db.relationship('RiskScore', backref='asset', uselist=False, lazy=True, cascade="all, delete-orphan")
    financial_risk = db.relationship('FinancialRisk', backref='asset', uselist=False, lazy=True, cascade="all, delete-orphan")
    alerts = db.relationship('Alert', backref='asset', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type,
            'value': self.value,
            'criticality': self.criticality,
            'business_importance': self.business_importance,
            'data_sensitivity': self.data_sensitivity,
            'internet_exposure': self.internet_exposure,
            'location': self.location,
            'owner': self.owner,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
