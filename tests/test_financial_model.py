import unittest
from flask import Flask
from database import db
from models.asset import Asset
from models.threat import Threat
from models.risk import FinancialRisk
from services.financial_model import calculate_aro, calculate_exposure_factor_financial, run_financial_model

class TestFinancialModel(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        db.init_app(self.app)
        
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        
    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_financial_calculations(self):
        # Create asset (Value: ₹50,00,000, Criticality: High, Exposed)
        asset = Asset(
            name='Crypto Vault',
            type='Database',
            value=5000000.0,
            criticality='High',
            internet_exposure=True
        )
        db.session.add(asset)
        db.session.commit()
        
        # Verify Exposure Factor (EF)
        # For High criticality = 0.7. Internet exposed (+0.1) = 0.8 EF
        ef = calculate_exposure_factor_financial(asset)
        self.assertAlmostEqual(ef, 0.8)
        
        # Verify Single Loss Expectancy (SLE)
        # SLE = Value * EF = ₹50,00,000 * 0.8 = ₹40,00,000
        sle = asset.value * ef
        self.assertAlmostEqual(sle, 4000000.0)
        
        # Add Threat (frequency = 3 -> 1.0 ARO)
        threat = Threat(
            name='Credential Extractor',
            type='Credential Theft',
            severity='High',
            frequency=3,
            likelihood=3,
            affected_asset_id=asset.id
        )
        db.session.add(threat)
        db.session.commit()
        
        # Verify ARO
        aro = calculate_aro(asset)
        self.assertAlmostEqual(aro, 1.0)
        
        # Verify ALE
        # ALE = SLE * ARO = 4,000,000 * 1.0 = 4,000,000
        ale = sle * aro
        self.assertAlmostEqual(ale, 4000000.0)


if __name__ == '__main__':
    unittest.main()
