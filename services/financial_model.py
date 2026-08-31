from database import db
from models.asset import Asset
from models.threat import Threat
from models.risk import FinancialRisk
from datetime import datetime

# Import ML service dynamically inside functions to prevent circular dependencies
def calculate_aro(asset):
    """
    Calculates Annual Rate of Occurrence (ARO) from active threats.
    """
    active_threats = Threat.query.filter(
        (Threat.status == 'Active') & 
        ((Threat.affected_asset_id == asset.id) | (Threat.affected_asset_id == None))
    ).all()
    
    if not active_threats:
        return 0.1  # Baseline low frequency (once in 10 years)
        
    frequency_map = {
        1: 0.1,  # Once in 10 years
        2: 0.5,  # Once in 2 years
        3: 1.0,  # Once a year
        4: 2.0,  # Twice a year
        5: 5.0   # Five times a year
    }
    
    # Let's sum the rates for all threats, capped at 10.0 per year
    total_aro = sum(frequency_map.get(t.frequency, 0.5) for t in active_threats)
    return min(10.0, max(0.1, total_aro))

def calculate_exposure_factor_financial(asset):
    """
    Financial Exposure Factor (EF) - representing the percentage of asset loss
    in a single incident. Range: 0.1 to 1.0.
    """
    criticality_ef = {
        'Low': 0.2,
        'Medium': 0.4,
        'High': 0.7,
        'Critical': 0.9
    }
    base_ef = criticality_ef.get(asset.criticality, 0.4)
    
    # Adjust for internet exposure
    if asset.internet_exposure:
        base_ef += 0.1
    else:
        base_ef -= 0.1
        
    return min(1.0, max(0.1, base_ef))

def run_financial_model():
    """
    Calculates SLE, ALE, and expected loss for all assets and saves to DB.
    """
    from services.ai_model import predict_incident_probability
    
    assets = Asset.query.all()
    updated_records = []
    
    for asset in assets:
        # 1. Single Loss Expectancy
        ef = calculate_exposure_factor_financial(asset)
        sle = asset.value * ef
        
        # 2. Annual Rate of Occurrence
        aro = calculate_aro(asset)
        
        # 3. Annualized Loss Expectancy
        ale = sle * aro
        
        # 4. Expected Loss using AI probability
        prob = predict_incident_probability(asset)  # between 0.0 and 1.0
        expected_loss = sle * prob
        
        # Save or update record
        fin_record = FinancialRisk.query.filter_by(asset_id=asset.id).first()
        if not fin_record:
            fin_record = FinancialRisk(asset_id=asset.id)
            db.session.add(fin_record)
            
        fin_record.sle = sle
        fin_record.ale = ale
        fin_record.expected_loss = expected_loss
        fin_record.updated_at = datetime.utcnow()
        updated_records.append(fin_record)
        
    db.session.commit()
    return updated_records
