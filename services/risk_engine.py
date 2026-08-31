from database import db
from models.asset import Asset
from models.vulnerability import Vulnerability
from models.threat import Threat
from models.security_control import SecurityControl
from models.risk import RiskScore
from datetime import datetime

def get_asset_controls(asset_type, all_controls):
    """
    Returns a list of security controls relevant to a specific asset type.
    """
    relevant_controls = []
    for ctrl in all_controls:
        name_lower = ctrl.name.lower()
        cat_lower = ctrl.category.lower()
        if asset_type == 'Server':
            if any(k in name_lower or k in cat_lower for k in ['firewall', 'ids', 'ips', 'edr', 'siem', 'patch']):
                relevant_controls.append(ctrl)
        elif asset_type == 'Database':
            if any(k in name_lower or k in cat_lower for k in ['encryption', 'backup', 'siem', 'access control', 'database']):
                relevant_controls.append(ctrl)
        elif asset_type == 'Endpoint':
            if any(k in name_lower or k in cat_lower for k in ['edr', 'mfa', 'awareness', 'antivirus']):
                relevant_controls.append(ctrl)
        elif asset_type == 'Web Application':
            if any(k in name_lower or k in cat_lower for k in ['firewall', 'mfa', 'waf', 'vulnerability', 'web']):
                relevant_controls.append(ctrl)
        elif asset_type == 'Cloud Resource':
            if any(k in name_lower or k in cat_lower for k in ['encryption', 'mfa', 'zero trust', 'iam', 'cloud']):
                relevant_controls.append(ctrl)
        elif asset_type == 'Network Device':
            if any(k in name_lower or k in cat_lower for k in ['firewall', 'ids', 'ips', 'vpn', 'network']):
                relevant_controls.append(ctrl)
        else: # IoT Device or generic
            if any(k in name_lower or k in cat_lower for k in ['firewall', 'zero trust', 'credential', 'iot']):
                relevant_controls.append(ctrl)
    return relevant_controls

def calculate_control_gap(asset, all_controls):
    """
    Calculates the control gap (1 - control effectiveness score) for the asset.
    """
    relevant_controls = get_asset_controls(asset.type, all_controls)
    active_controls = [c for c in relevant_controls if c.status == 'Active']
    
    if not active_controls:
        return 1.0  # Maximum gap (100% risk exposure)
        
    # Average protection factor of active controls
    total_protection = 0.0
    for ctrl in active_controls:
        # Protection is effectiveness % * coverage %
        total_protection += (ctrl.effectiveness / 100.0) * (ctrl.coverage / 100.0)
        
    avg_protection = total_protection / len(relevant_controls) if relevant_controls else 0.0
    # Cap avg_protection at 0.95 to ensure there is always some residual risk
    avg_protection = min(0.95, avg_protection)
    
    return max(0.05, 1.0 - avg_protection)

def calculate_vulnerability_factor(asset):
    """
    Calculates vulnerability factor based on CVSS score and KEV status.
    """
    unpatched_vulns = [v for v in asset.vulnerabilities if not v.patch_status]
    if not unpatched_vulns:
        return 0.1  # Low default vulnerability factor
        
    max_cvss = max(v.cvss_score for v in unpatched_vulns)
    vuln_factor = max_cvss / 10.0
    
    # Adjust for public exploit availability or CISA KEV listing
    has_kev = any(v.kev_status for v in unpatched_vulns)
    has_public_exploit = any(v.public_exploit for v in unpatched_vulns)
    
    if has_kev:
        vuln_factor += 0.2
    elif has_public_exploit:
        vuln_factor += 0.1
        
    return min(1.0, vuln_factor)

def calculate_likelihood(asset):
    """
    Calculates likelihood based on threats targeting the asset.
    """
    # Active threats targeting this asset specifically or all assets (affected_asset_id is Null)
    active_threats = Threat.query.filter(
        (Threat.status == 'Active') & 
        ((Threat.affected_asset_id == asset.id) | (Threat.affected_asset_id == None))
    ).all()
    
    if not active_threats:
        return 0.2  # Low likelihood baseline
        
    # Get maximum threat likelihood (on 1-5 scale)
    max_likelihood = max(t.likelihood for t in active_threats)
    # Convert 1-5 scale to 0.2-1.0
    return max_likelihood / 5.0

def calculate_impact(asset):
    """
    Calculates impact based on asset criticality.
    """
    criticality_map = {
        'Low': 1.0,
        'Medium': 2.0,
        'High': 4.0,
        'Critical': 5.0
    }
    score = criticality_map.get(asset.criticality, 2.0)
    return score / 5.0

def calculate_exposure_factor(asset):
    """
    Exposure multiplier based on internet exposure.
    """
    return 1.2 if asset.internet_exposure else 0.8

def get_risk_level(normalized_score):
    """
    Classify normalized risk score into risk levels.
    """
    if normalized_score <= 25.0:
        return 'Low'
    elif normalized_score <= 50.0:
        return 'Medium'
    elif normalized_score <= 75.0:
        return 'High'
    else:
        return 'Critical'

def recalculate_asset_risk(asset, all_controls):
    """
    Recalculates risk parameters for a single asset and updates RiskScore.
    """
    likelihood = calculate_likelihood(asset)
    impact = calculate_impact(asset)
    exposure = calculate_exposure_factor(asset)
    vuln_factor = calculate_vulnerability_factor(asset)
    control_gap = calculate_control_gap(asset, all_controls)
    
    # Risk Score Formula
    raw_score = likelihood * impact * exposure * vuln_factor * control_gap
    
    # Normalizing raw score (maximum possible raw score is 1.0 * 1.0 * 1.2 * 1.0 * 1.0 = 1.2)
    normalized_score = min(100.0, max(0.0, (raw_score / 1.2) * 100.0))
    risk_level = get_risk_level(normalized_score)
    
    # Update or create RiskScore record
    risk_record = RiskScore.query.filter_by(asset_id=asset.id).first()
    if not risk_record:
        risk_record = RiskScore(asset_id=asset.id)
        db.session.add(risk_record)
        
    risk_record.likelihood_score = likelihood * 5.0
    risk_record.impact_score = impact * 5.0
    risk_record.raw_score = raw_score
    risk_record.normalized_score = normalized_score
    risk_record.risk_level = risk_level
    risk_record.updated_at = datetime.utcnow()
    
    return risk_record

def run_risk_engine():
    """
    Runs risk calculations across all assets in the database.
    """
    assets = Asset.query.all()
    all_controls = SecurityControl.query.all()
    
    updated_records = []
    for asset in assets:
        record = recalculate_asset_risk(asset, all_controls)
        updated_records.append(record)
        
    db.session.commit()
    return updated_records
