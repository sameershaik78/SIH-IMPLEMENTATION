import os
import joblib
import numpy as np
from database import db
from models.asset import Asset
from models.vulnerability import Vulnerability
from models.threat import Threat
from models.security_control import SecurityControl
from models.incident import Incident

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ml')
MODEL_PATH = os.path.join(MODEL_DIR, 'model.pkl')

def extract_features(asset):
    """
    Extracts the feature vector for a given asset.
    Features:
    1. cvss_score
    2. asset_criticality
    3. asset_value
    4. threat_frequency
    5. threat_severity
    6. exploitability
    7. internet_exposure
    8. patch_status
    9. control_effectiveness
    10. historical_incidents
    11. attack_surface
    """
    # 1. cvss_score (max of unpatched vulns)
    unpatched = [v for v in asset.vulnerabilities if not v.patch_status]
    cvss = max([v.cvss_score for v in unpatched]) if unpatched else 0.0
    
    # 2. asset_criticality
    crit_map = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
    crit = crit_map.get(asset.criticality, 2)
    
    # 3. asset_value (scaled for numerical stability in tree models, e.g. log10)
    val = np.log10(max(100.0, asset.value))
    
    # 4. threat_frequency
    active_threats = Threat.query.filter(
        (Threat.status == 'Active') & 
        ((Threat.affected_asset_id == asset.id) | (Threat.affected_asset_id == None))
    ).all()
    threat_freq = sum(t.frequency for t in active_threats) if active_threats else 0.0
    
    # 5. threat_severity
    sev_map = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
    threat_sev = max([sev_map.get(t.severity, 1) for t in active_threats]) if active_threats else 0.0
    
    # 6. exploitability
    expl = max([v.exploitability for v in unpatched]) if unpatched else 1.0
    
    # 7. internet_exposure
    exp = 1 if asset.internet_exposure else 0
    
    # 8. patch_status (1 if all patched, 0 if any unpatched)
    patch = 1 if (asset.vulnerabilities and all(v.patch_status for v in asset.vulnerabilities)) else 0
    
    # 9. control_effectiveness
    from services.risk_engine import get_asset_controls
    all_controls = SecurityControl.query.all()
    relevant_controls = get_asset_controls(asset.type, all_controls)
    active_controls = [c for c in relevant_controls if c.status == 'Active']
    
    if relevant_controls:
        ctrl_eff = sum((c.effectiveness / 100.0) * (c.coverage / 100.0) for c in active_controls) / len(relevant_controls)
    else:
        ctrl_eff = 0.0
        
    # 10. historical_incidents
    hist_incidents = len(asset.incidents)
    
    # 11. attack_surface
    surface_map = {
        'Web Application': 5,
        'Server': 4,
        'Cloud Resource': 3,
        'Database': 2,
        'Network Device': 2,
        'Endpoint': 1,
        'IoT Device': 3
    }
    surface = surface_map.get(asset.type, 2)
    
    return [cvss, crit, val, threat_freq, threat_sev, expl, exp, patch, ctrl_eff, hist_incidents, surface]

def predict_incident_probability(asset):
    """
    Predicts incident probability using the trained machine learning model.
    Falls back to a logic-based heuristic if the model is not trained.
    """
    features = extract_features(asset)
    
    if os.path.exists(MODEL_PATH):
        try:
            model_data = joblib.load(MODEL_PATH)
            model = model_data['model']
            
            # Predict probability of class 1 (incident occurred)
            # The model is trained on a 2D array, so we reshape features
            features_arr = np.array(features).reshape(1, -1)
            prob = model.predict_proba(features_arr)[0][1]
            return float(prob)
        except Exception as e:
            # Print error or log it
            print(f"Error executing ML model: {e}. Falling back to heuristic.")
            
    # Heuristic Fallback:
    # Combine normalized factors: CVSS (40%), Exposure (30%), Control Gap (30%)
    cvss = features[0]
    exp = features[6]
    ctrl_eff = features[8]
    
    cvss_factor = cvss / 10.0
    exposure_factor = exp
    control_gap = 1.0 - ctrl_eff
    
    prob = (cvss_factor * 0.40) + (exposure_factor * 0.30) + (control_gap * 0.30)
    # Clamp probability
    return min(0.99, max(0.01, float(prob)))
