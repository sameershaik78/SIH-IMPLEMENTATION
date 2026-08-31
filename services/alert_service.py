from database import db
from models.alert import Alert
from models.vulnerability import Vulnerability
from models.asset import Asset
from models.threat import Threat
from models.security_control import SecurityControl
from models.risk import RiskScore, FinancialRisk
from services.ai_model import predict_incident_probability
from datetime import datetime

def create_alert_if_not_exists(alert_type, severity, title, message, asset_id=None, risk_score=None):
    """
    Checks if a similar unread alert already exists to prevent alert duplication.
    """
    existing = Alert.query.filter_by(
        alert_type=alert_type,
        asset_id=asset_id,
        title=title,
        status='Unread'
    ).first()
    
    if not existing:
        alert = Alert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message,
            asset_id=asset_id,
            risk_score=risk_score,
            created_at=datetime.utcnow()
        )
        db.session.add(alert)
        return True
    return False

def evaluate_alerts():
    """
    Evaluates system metrics and raises alerts for high risks, vulnerable assets, or control gaps.
    """
    # 1. Evaluate Vulnerabilities
    vulns = Vulnerability.query.filter(Vulnerability.patch_status == False).all()
    for v in vulns:
        if v.cvss_score >= 9.0:
            create_alert_if_not_exists(
                'VULNERABILITY', 'CRITICAL',
                f"Critical Vulnerability {v.cve_id} Detected",
                f"Unpatched vulnerability {v.cve_id} with CVSS {v.cvss_score} detected on asset '{v.asset.name}'.",
                v.asset_id, v.cvss_score * 10
            )
        elif v.cvss_score >= 7.0:
            create_alert_if_not_exists(
                'VULNERABILITY', 'HIGH',
                f"High Vulnerability {v.cve_id} Detected",
                f"Unpatched vulnerability {v.cve_id} with CVSS {v.cvss_score} detected on asset '{v.asset.name}'.",
                v.asset_id, v.cvss_score * 10
            )
            
    # 2. Evaluate Risks
    risks = RiskScore.query.all()
    for r in risks:
        if r.normalized_score >= 75.0:
            create_alert_if_not_exists(
                'RISK_INCREASE', 'CRITICAL',
                f"Critical Risk Level on Asset: {r.asset.name}",
                f"The risk score of asset '{r.asset.name}' has reached {r.normalized_score:.1f}% ({r.risk_level}). Immediate mitigation recommended.",
                r.asset_id, r.normalized_score
            )
        elif r.normalized_score >= 50.0:
            create_alert_if_not_exists(
                'RISK_INCREASE', 'HIGH',
                f"High Risk Level on Asset: {r.asset.name}",
                f"The risk score of asset '{r.asset.name}' is {r.normalized_score:.1f}% ({r.risk_level}). Review security controls.",
                r.asset_id, r.normalized_score
            )

    # 3. Evaluate ML Incident Probabilities
    assets = Asset.query.all()
    for asset in assets:
        prob = predict_incident_probability(asset)
        if prob >= 0.75:
            create_alert_if_not_exists(
                'RISK_INCREASE', 'CRITICAL',
                f"High Incident Probability on {asset.name}",
                f"AI Risk Engine predicts a {prob*100:.1f}% chance of a security incident on asset '{asset.name}' in the next 12 months.",
                asset.id, prob * 100.0
            )

    # 4. Evaluate Security Controls
    controls = SecurityControl.query.all()
    for ctrl in controls:
        if ctrl.status == 'Active':
            if ctrl.coverage < 40.0:
                create_alert_if_not_exists(
                    'CONTROL_WEAKNESS', 'WARNING',
                    f"Low Coverage for Control: {ctrl.name}",
                    f"Active security control '{ctrl.name}' has low organizational coverage of {ctrl.coverage}%.",
                    None
                )
            if ctrl.effectiveness < 50.0:
                create_alert_if_not_exists(
                    'CONTROL_WEAKNESS', 'WARNING',
                    f"Low Effectiveness for Control: {ctrl.name}",
                    f"Active security control '{ctrl.name}' has low effectiveness of {ctrl.effectiveness}%.",
                    None
                )
        elif ctrl.status in ['Inactive', 'Proposed']:
            # Suggest optimization if there are high-risk assets and this control is highly effective
            critical_risks = [r for r in risks if r.normalized_score >= 50.0]
            if critical_risks and ctrl.risk_reduction_factor >= 50.0:
                create_alert_if_not_exists(
                    'BUDGET_OPPORTUNITY', 'INFO',
                    f"Security Investment Opportunity: {ctrl.name}",
                    f"Implementing control '{ctrl.name}' would provide {ctrl.risk_reduction_factor}% risk reduction. Recommended to run Budget Optimizer.",
                    None
                )
                
    db.session.commit()
