import os
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_cors import CORS
from database import db
from config import Config

# Import Models
from models.user import User
from models.asset import Asset
from models.vulnerability import Vulnerability
from models.threat import Threat
from models.security_control import SecurityControl
from models.incident import Incident
from models.risk import RiskScore, FinancialRisk
from models.investment import Investment, Recommendation
from models.alert import Alert

# Import Services
from services.risk_engine import run_risk_engine, recalculate_asset_risk
from services.financial_model import run_financial_model
from services.alert_service import evaluate_alerts
from services.optimizer import run_optimization
from services.ai_model import predict_incident_probability

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize Extensions
    db.init_app(app)
    CORS(app)
    
    return app

app = create_app()

# --- Auth Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized. Please login.'}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_role' not in session or session['user_role'] not in roles:
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Forbidden. Insufficient permissions.'}), 403
                flash('Access Denied: You do not have permission to view this page.')
                return redirect(url_for('dashboard_page'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Page Routes ---
@app.route('/')
def index_redirect():
    if 'user_id' in session:
        return redirect(url_for('dashboard_page'))
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['user_role'] = user.role
            return redirect(url_for('dashboard_page'))
        else:
            flash('Invalid username or password.', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/dashboard')
@login_required
def dashboard_page():
    return render_template('dashboard.html')

@app.route('/assets')
@login_required
def assets_page():
    return render_template('assets.html')

@app.route('/vulnerabilities')
@login_required
def vulnerabilities_page():
    return render_template('vulnerabilities.html')

@app.route('/threats')
@login_required
def threats_page():
    return render_template('threats.html')

@app.route('/controls')
@login_required
def controls_page():
    return render_template('controls.html')

@app.route('/risks')
@login_required
def risks_page():
    return render_template('risks.html')

@app.route('/optimizer')
@login_required
def optimizer_page():
    return render_template('optimizer.html')

@app.route('/alerts')
@login_required
def alerts_page():
    return render_template('alerts.html')

@app.route('/reports')
@login_required
def reports_page():
    return render_template('reports.html')

@app.route('/settings')
@login_required
def settings_page():
    return render_template('settings.html')


# --- REST API Endpoints ---

# Auth check endpoint
@app.route('/api/auth/me', methods=['GET'])
@login_required
def api_auth_me():
    return jsonify({
        'id': session['user_id'],
        'username': session['username'],
        'role': session['user_role']
    })

# Assets CRUD
@app.route('/api/assets', methods=['GET'])
@login_required
def api_get_assets():
    assets = Asset.query.all()
    # Join with risk and financial records
    res = []
    for a in assets:
        ad = a.to_dict()
        ad['risk_score'] = a.risk_score.normalized_score if a.risk_score else 0.0
        ad['risk_level'] = a.risk_score.risk_level if a.risk_score else 'Low'
        ad['expected_loss'] = a.financial_risk.expected_loss if a.financial_risk else 0.0
        res.append(ad)
    return jsonify(res)

@app.route('/api/assets', methods=['POST'])
@login_required
@role_required(['Admin', 'Security Analyst'])
def api_create_asset():
    data = request.json
    try:
        asset = Asset(
            name=data['name'],
            type=data['type'],
            value=float(data['value']),
            criticality=data['criticality'],
            business_importance=data.get('business_importance', ''),
            data_sensitivity=data.get('data_sensitivity', ''),
            internet_exposure=bool(data.get('internet_exposure', False)),
            location=data.get('location', ''),
            owner=data.get('owner', '')
        )
        db.session.add(asset)
        db.session.commit()
        
        # Trigger background updates
        run_risk_engine()
        run_financial_model()
        evaluate_alerts()
        
        return jsonify(asset.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/assets/<int:asset_id>', methods=['PUT'])
@login_required
@role_required(['Admin', 'Security Analyst'])
def api_update_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    data = request.json
    try:
        asset.name = data.get('name', asset.name)
        asset.type = data.get('type', asset.type)
        asset.value = float(data.get('value', asset.value))
        asset.criticality = data.get('criticality', asset.criticality)
        asset.business_importance = data.get('business_importance', asset.business_importance)
        asset.data_sensitivity = data.get('data_sensitivity', asset.data_sensitivity)
        asset.internet_exposure = bool(data.get('internet_exposure', asset.internet_exposure))
        asset.location = data.get('location', asset.location)
        asset.owner = data.get('owner', asset.owner)
        asset.status = data.get('status', asset.status)
        
        db.session.commit()
        
        # Trigger recalculations
        run_risk_engine()
        run_financial_model()
        evaluate_alerts()
        
        return jsonify(asset.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/assets/<int:asset_id>', methods=['DELETE'])
@login_required
@role_required(['Admin'])
def api_delete_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    try:
        db.session.delete(asset)
        db.session.commit()
        
        # Trigger recalculations
        run_risk_engine()
        run_financial_model()
        evaluate_alerts()
        
        return jsonify({'message': 'Asset deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400


# Vulnerabilities API
@app.route('/api/vulnerabilities', methods=['GET'])
@login_required
def api_get_vulnerabilities():
    vulns = Vulnerability.query.all()
    return jsonify([v.to_dict() for v in vulns])

@app.route('/api/vulnerabilities', methods=['POST'])
@login_required
@role_required(['Admin', 'Security Analyst'])
def api_create_vulnerability():
    data = request.json
    try:
        vuln = Vulnerability(
            cve_id=data['cve_id'],
            asset_id=int(data['asset_id']),
            cvss_score=float(data['cvss_score']),
            severity=data['severity'],
            exploitability=float(data.get('exploitability', 1.0)),
            attack_vector=data.get('attack_vector', 'Network'),
            patch_status=bool(data.get('patch_status', False)),
            public_exploit=bool(data.get('public_exploit', False)),
            kev_status=bool(data.get('kev_status', False))
        )
        db.session.add(vuln)
        db.session.commit()
        
        # Trigger calculations
        run_risk_engine()
        run_financial_model()
        evaluate_alerts()
        
        return jsonify(vuln.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/vulnerabilities/<int:vuln_id>', methods=['PUT'])
@login_required
@role_required(['Admin', 'Security Analyst'])
def api_update_vulnerability(vuln_id):
    vuln = Vulnerability.query.get_or_404(vuln_id)
    data = request.json
    try:
        vuln.patch_status = bool(data.get('patch_status', vuln.patch_status))
        vuln.cvss_score = float(data.get('cvss_score', vuln.cvss_score))
        vuln.severity = data.get('severity', vuln.severity)
        vuln.public_exploit = bool(data.get('public_exploit', vuln.public_exploit))
        vuln.kev_status = bool(data.get('kev_status', vuln.kev_status))
        
        db.session.commit()
        
        # Trigger calculations
        run_risk_engine()
        run_financial_model()
        evaluate_alerts()
        
        return jsonify(vuln.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400


# Threats API
@app.route('/api/threats', methods=['GET'])
@login_required
def api_get_threats():
    threats = Threat.query.all()
    return jsonify([t.to_dict() for t in threats])

@app.route('/api/threats', methods=['POST'])
@login_required
@role_required(['Admin', 'Security Analyst'])
def api_create_threat():
    data = request.json
    try:
        threat = Threat(
            name=data['name'],
            type=data['type'],
            severity=data['severity'],
            frequency=int(data.get('frequency', 1)),
            likelihood=int(data.get('likelihood', 1)),
            attack_vector=data.get('attack_vector', ''),
            threat_actor=data.get('threat_actor', ''),
            affected_asset_id=int(data['affected_asset_id']) if data.get('affected_asset_id') else None,
            description=data.get('description', '')
        )
        db.session.add(threat)
        db.session.commit()
        
        # Recalculate
        run_risk_engine()
        run_financial_model()
        evaluate_alerts()
        
        return jsonify(threat.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400


# Security Controls API
@app.route('/api/security-controls', methods=['GET'])
@login_required
def api_get_security_controls():
    controls = SecurityControl.query.all()
    return jsonify([c.to_dict() for c in controls])

@app.route('/api/security-controls/<int:control_id>', methods=['PUT'])
@login_required
@role_required(['Admin', 'Security Analyst'])
def api_update_security_control(control_id):
    control = SecurityControl.query.get_or_404(control_id)
    data = request.json
    try:
        control.status = data.get('status', control.status)
        control.coverage = float(data.get('coverage', control.coverage))
        control.effectiveness = float(data.get('effectiveness', control.effectiveness))
        
        db.session.commit()
        
        # Recalculate
        run_risk_engine()
        run_financial_model()
        evaluate_alerts()
        
        return jsonify(control.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400


# Dashboard Metrics API
@app.route('/api/dashboard', methods=['GET'])
@login_required
def api_get_dashboard():
    assets = Asset.query.all()
    vulns = Vulnerability.query.filter_by(patch_status=False).all()
    threats = Threat.query.filter_by(status='Active').all()
    controls = SecurityControl.query.all()
    
    # Calculate Overall Stats
    risk_scores = [a.risk_score.normalized_score for a in assets if a.risk_score]
    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
    
    financial_losses = [a.financial_risk.ale for a in assets if a.financial_risk]
    total_ale = sum(financial_losses)
    
    expected_losses = [a.financial_risk.expected_loss for a in assets if a.financial_risk]
    total_expected_loss = sum(expected_losses)
    
    critical_vulns_count = len([v for v in vulns if v.cvss_score >= 9.0])
    active_threats_count = len(threats)
    
    # Control coverage
    active_controls = [c for c in controls if c.status == 'Active']
    avg_coverage = sum(c.coverage for c in active_controls) / len(active_controls) if active_controls else 0.0
    
    # ML metrics if file is present
    ml_metrics = None
    import joblib
    MODEL_PATH = os.path.join(os.path.dirname(__file__), 'ml', 'model.pkl')
    if os.path.exists(MODEL_PATH):
        try:
            model_data = joblib.load(MODEL_PATH)
            ml_metrics = model_data.get('metrics')
        except:
            pass
            
    # Risk levels breakdown
    levels = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
    for a in assets:
        lvl = a.risk_score.risk_level if a.risk_score else 'Low'
        levels[lvl] = levels.get(lvl, 0) + 1
        
    return jsonify({
        'overall_risk_score': avg_risk,
        'total_annual_loss_expectancy': total_ale,
        'total_expected_loss': total_expected_loss,
        'critical_vulnerabilities': critical_vulns_count,
        'active_threats': active_threats_count,
        'control_coverage_pct': avg_coverage,
        'ml_metrics': ml_metrics,
        'risk_distribution': levels
    })


# Risk Explanations API
@app.route('/api/risks', methods=['GET'])
@login_required
def api_get_risks():
    assets = Asset.query.all()
    res = []
    for a in assets:
        res.append({
            'asset_id': a.id,
            'asset_name': a.name,
            'asset_type': a.type,
            'criticality': a.criticality,
            'risk_score': a.risk_score.normalized_score if a.risk_score else 0.0,
            'risk_level': a.risk_score.risk_level if a.risk_score else 'Low',
            'expected_loss': a.financial_risk.expected_loss if a.financial_risk else 0.0
        })
    # Sort by risk score descending
    res = sorted(res, key=lambda x: x['risk_score'], reverse=True)
    return jsonify(res)

@app.route('/api/risks/<int:asset_id>', methods=['GET'])
@login_required
def api_get_risk_detail(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    
    # Calculate explainability components
    unpatched = [v for v in asset.vulnerabilities if not v.patch_status]
    cvss = max([v.cvss_score for v in unpatched]) if unpatched else 0.0
    
    crit_map = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 5}
    crit = crit_map.get(asset.criticality, 2)
    
    active_threats = Threat.query.filter(
        (Threat.status == 'Active') & 
        ((Threat.affected_asset_id == asset.id) | (Threat.affected_asset_id == None))
    ).all()
    threat_freq = max([t.frequency for t in active_threats]) if active_threats else 0
    
    from services.risk_engine import get_asset_controls, calculate_control_gap
    all_controls = SecurityControl.query.all()
    relevant_controls = get_asset_controls(asset.type, all_controls)
    active_ctrls = [c for c in relevant_controls if c.status == 'Active']
    
    control_gap = calculate_control_gap(asset, all_controls)
    
    # Incident probability
    prob = predict_incident_probability(asset)
    
    explanation = []
    if cvss >= 7.0:
        explanation.append(f"Contains unpatched vulnerability ({unpatched[0].cve_id}) with critical CVSS rating of {cvss}.")
    if asset.internet_exposure:
        explanation.append("Asset is directly internet exposed, broadening the attack surface.")
    if asset.criticality == 'Critical' or asset.criticality == 'High':
        explanation.append(f"Asset criticality is rated '{asset.criticality}' due to high business dependency ({asset.business_importance}).")
    if control_gap > 0.5:
        explanation.append(f"Security control coverage gap is high ({control_gap*100:.0f}% unprotected).")
    if threat_freq >= 4:
        explanation.append("Asset is targeted by active threat campaigns with high occurrence rates.")
        
    if not explanation:
        explanation.append("Asset is well protected with low active threat frequency.")
        
    return jsonify({
        'asset_id': asset.id,
        'asset_name': asset.name,
        'asset_type': asset.type,
        'asset_value': asset.value,
        'criticality': asset.criticality,
        'risk_score': asset.risk_score.normalized_score if asset.risk_score else 0.0,
        'risk_level': asset.risk_score.risk_level if asset.risk_score else 'Low',
        'expected_loss': asset.financial_risk.expected_loss if asset.financial_risk else 0.0,
        'sle': asset.financial_risk.sle if asset.financial_risk else 0.0,
        'ale': asset.financial_risk.ale if asset.financial_risk else 0.0,
        'incident_probability': prob,
        'factors': {
            'cvss_severity': cvss * 10,  # 0 - 100
            'asset_criticality': (crit / 5.0) * 100,
            'internet_exposure': 100 if asset.internet_exposure else 20,
            'threat_frequency': (threat_freq / 5.0) * 100,
            'control_gap': control_gap * 100
        },
        'explanation_bullets': explanation
    })


# Alerts API
@app.route('/api/alerts', methods=['GET'])
@login_required
def api_get_alerts():
    alerts = Alert.query.order_by(Alert.created_at.desc()).all()
    return jsonify([al.to_dict() for al in alerts])

@app.route('/api/alerts/<int:alert_id>', methods=['PUT'])
@login_required
@role_required(['Admin', 'Security Analyst'])
def api_read_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    try:
        alert.status = 'Read'
        db.session.commit()
        return jsonify(alert.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400


# Optimization API
@app.route('/api/optimize', methods=['POST'])
@login_required
@role_required(['Admin', 'Security Analyst', 'Executive'])
def api_optimize():
    data = request.json
    budget = float(data.get('budget', 1000000.0)) # Default ₹10,00,000
    
    try:
        res = run_optimization(budget)
        
        # Save Investment results to database
        investment = Investment(
            budget=budget,
            total_cost=res['investment_cost'],
            expected_risk_reduction=res['risk_reduction_pct'],
            expected_loss_before=res['expected_loss_before'],
            expected_loss_after=res['expected_loss_after'],
            roi=res['roi']
        )
        db.session.add(investment)
        db.session.commit()
        
        # Record Recommendations
        all_controls = SecurityControl.query.all()
        rec_ids = [c['id'] for c in res['recommended_controls']]
        for ctrl in all_controls:
            rec = Recommendation(
                investment_id=investment.id,
                control_id=ctrl.id,
                recommended=(ctrl.id in rec_ids)
            )
            db.session.add(rec)
        db.session.commit()
        
        return jsonify(res)
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400


# Recalculate Risk Endpoint
@app.route('/api/recalculate-risk', methods=['POST'])
@login_required
@role_required(['Admin', 'Security Analyst'])
def api_recalculate():
    try:
        run_risk_engine()
        run_financial_model()
        evaluate_alerts()
        return jsonify({'message': 'System risk metrics recalculated successfully.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Train ML Model Endpoint
@app.route('/api/train-ml', methods=['POST'])
@login_required
@role_required(['Admin'])
def api_train_ml():
    try:
        from ml.train_model import train_and_save
        train_and_save()
        return jsonify({'message': 'Random Forest Classifier trained successfully.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # Initialize Database tables if not already created
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)

