import unittest
from flask import Flask
from database import db
from config import Config
from models.asset import Asset
from models.vulnerability import Vulnerability
from models.threat import Threat
from models.security_control import SecurityControl
from models.risk import RiskScore
from services.risk_engine import recalculate_asset_risk, run_risk_engine

class TestRiskEngine(unittest.TestCase):
    def setUp(self):
        # Create an in-memory database app context
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.app.config['SECRET_KEY'] = 'testing-key'
        
        db.init_app(self.app)
        
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        
    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        
    def test_risk_score_range_and_levels(self):
        # 1. Create a dummy asset
        asset = Asset(
            name='Test Server',
            type='Server',
            value=1000000.0,
            criticality='Critical',
            internet_exposure=True
        )
        db.session.add(asset)
        db.session.commit()
        
        # 2. Add Critical CVSS Vulnerability
        vuln = Vulnerability(
            cve_id='CVE-9999-9999',
            asset_id=asset.id,
            cvss_score=10.0,
            severity='Critical',
            exploitability=3.0,
            patch_status=False
        )
        db.session.add(vuln)
        
        # 3. Add Threat targeting the asset
        threat = Threat(
            name='Test Threat',
            type='Malware',
            severity='Critical',
            frequency=5,
            likelihood=5,
            affected_asset_id=asset.id
        )
        db.session.add(threat)
        db.session.commit()
        
        # 4. Run recalculation with NO security controls (max risk)
        controls = []
        risk_rec = recalculate_asset_risk(asset, controls)
        
        # Assertions
        self.assertIsNotNone(risk_rec)
        self.assertGreaterEqual(risk_rec.normalized_score, 0.0)
        self.assertLessEqual(risk_rec.normalized_score, 100.0)
        self.assertEqual(risk_rec.risk_level, 'Critical')
        
        # Capture the initial risk score before recalculating with controls
        initial_score = risk_rec.normalized_score
        
        # 5. Add security controls and re-verify risk reduction
        ctrl = SecurityControl(
            name='Test Firewall',
            category='Network',
            implementation_cost=10000,
            maintenance_cost=1000,
            effectiveness=100.0,  # 100% effective
            coverage=100.0,       # 100% coverage
            status='Active',
            risk_reduction_factor=90.0
        )
        db.session.add(ctrl)
        db.session.commit()
        
        risk_rec_reduced = recalculate_asset_risk(asset, [ctrl])
        # Assert risk score is reduced after applying controls
        self.assertLess(risk_rec_reduced.normalized_score, initial_score)
        self.assertGreaterEqual(risk_rec_reduced.normalized_score, 0.0)
        self.assertLessEqual(risk_rec_reduced.normalized_score, 100.0)


if __name__ == '__main__':
    unittest.main()
