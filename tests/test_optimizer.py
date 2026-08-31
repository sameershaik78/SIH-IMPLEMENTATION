import unittest
from flask import Flask
from database import db
from models.asset import Asset
from models.security_control import SecurityControl
from services.optimizer import run_optimization

class TestOptimizer(unittest.TestCase):
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

    def test_budget_constraints(self):
        # Create an asset
        asset = Asset(
            name='Internal Portal',
            type='Web Application',
            value=100000.0,
            criticality='Medium',
            internet_exposure=False
        )
        db.session.add(asset)
        
        # Add 3 proposed controls with different costs and reduction factors
        ctrl1 = SecurityControl(
            name='Cheap Control', category='Web Application',
            implementation_cost=10000.0, maintenance_cost=5000.0,  # Total: 15,000
            effectiveness=80.0, coverage=50.0, status='Proposed',
            risk_reduction_factor=40.0
        )
        ctrl2 = SecurityControl(
            name='Medium Control', category='Web Application',
            implementation_cost=50000.0, maintenance_cost=10000.0, # Total: 60,000
            effectiveness=90.0, coverage=60.0, status='Proposed',
            risk_reduction_factor=70.0
        )
        ctrl3 = SecurityControl(
            name='Expensive Control', category='Web Application',
            implementation_cost=100000.0, maintenance_cost=20000.0, # Total: 120,000
            effectiveness=95.0, coverage=80.0, status='Proposed',
            risk_reduction_factor=95.0
        )
        db.session.add_all([ctrl1, ctrl2, ctrl3])
        db.session.commit()
        
        # Scenario A: Budget is 50,000 (Should pick Cheap Control only)
        res_a = run_optimization(50000.0)
        self.assertLessEqual(res_a['investment_cost'], 50000.0)
        recommended_names_a = [c['name'] for c in res_a['recommended_controls']]
        self.assertIn('Cheap Control', recommended_names_a)
        self.assertNotIn('Medium Control', recommended_names_a)
        self.assertNotIn('Expensive Control', recommended_names_a)
        
        # Scenario B: Budget is 80,000 (Should pick Cheap + Medium, Total: 75,000)
        res_b = run_optimization(80000.0)
        self.assertLessEqual(res_b['investment_cost'], 80000.0)
        recommended_names_b = [c['name'] for c in res_b['recommended_controls']]
        self.assertIn('Cheap Control', recommended_names_b)
        self.assertIn('Medium Control', recommended_names_b)
        self.assertNotIn('Expensive Control', recommended_names_b)
        
        # Scenario C: Budget is 200,000 (Should pick all controls, Total: 195,000)
        res_c = run_optimization(200000.0)
        self.assertLessEqual(res_c['investment_cost'], 200000.0)
        recommended_names_c = [c['name'] for c in res_c['recommended_controls']]
        self.assertEqual(len(recommended_names_c), 3)

if __name__ == '__main__':
    unittest.main()
