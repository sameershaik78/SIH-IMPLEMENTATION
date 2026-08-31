import pulp
from models.asset import Asset
from models.security_control import SecurityControl
from models.threat import Threat
from models.risk import RiskScore, FinancialRisk
from services.risk_engine import calculate_likelihood, calculate_impact, calculate_exposure_factor, calculate_vulnerability_factor, get_risk_level
from services.financial_model import calculate_exposure_factor_financial, calculate_aro
from services.ai_model import predict_incident_probability

def simulate_system(controls_state):
    """
    Simulates the entire risk engine in memory with a given controls state dictionary:
    {control_id: 'Active' / 'Inactive' / 'Proposed'}
    Returns:
      {asset_id: {'risk_score': float, 'expected_loss': float}}
    """
    assets = Asset.query.all()
    all_controls = SecurityControl.query.all()
    
    # Create a mapping of controls with simulated status
    simulated_controls = []
    for c in all_controls:
        # Create a shallow copy or object representation with simulated status
        class SimControl:
            def __init__(self, original, status):
                self.id = original.id
                self.name = original.name
                self.category = original.category
                self.effectiveness = original.effectiveness
                self.coverage = original.coverage
                self.status = status
                self.risk_reduction_factor = original.risk_reduction_factor
        
        status = controls_state.get(c.id, c.status)
        simulated_controls.append(SimControl(c, status))
        
    results = {}
    for asset in assets:
        # Calculate likelihood, impact, exposure, vuln factor (these don't depend on controls directly)
        likelihood = calculate_likelihood(asset)
        impact = calculate_impact(asset)
        exposure = calculate_exposure_factor(asset)
        vuln_factor = calculate_vulnerability_factor(asset)
        
        # Calculate control gap using simulated controls
        from services.risk_engine import get_asset_controls
        relevant_controls = get_asset_controls(asset.type, simulated_controls)
        active_controls = [c for c in relevant_controls if c.status == 'Active']
        
        if not active_controls:
            control_gap = 1.0
        else:
            total_protection = sum((c.effectiveness / 100.0) * (c.coverage / 100.0) for c in active_controls)
            avg_protection = total_protection / len(relevant_controls) if relevant_controls else 0.0
            avg_protection = min(0.95, avg_protection)
            control_gap = max(0.05, 1.0 - avg_protection)
            
        # Sim Risk Score
        raw_score = likelihood * impact * exposure * vuln_factor * control_gap
        normalized_score = min(100.0, max(0.0, (raw_score / 1.2) * 100.0))
        
        # Sim Expected Loss
        ef = calculate_exposure_factor_financial(asset)
        sle = asset.value * ef
        
        # Predict probability - since predict_incident_probability extracts control effectiveness,
        # we compute simulated control effectiveness for the feature vector
        if relevant_controls:
            ctrl_eff = sum((c.effectiveness / 100.0) * (c.coverage / 100.0) for c in active_controls) / len(relevant_controls)
        else:
            ctrl_eff = 0.0
            
        # Heuristic fallback probability simulator using simulated control effectiveness
        unpatched = [v for v in asset.vulnerabilities if not v.patch_status]
        cvss = max([v.cvss_score for v in unpatched]) if unpatched else 0.0
        exp = 1 if asset.internet_exposure else 0
        cvss_factor = cvss / 10.0
        exposure_factor = exp
        sim_prob = (cvss_factor * 0.40) + (exposure_factor * 0.30) + ((1.0 - ctrl_eff) * 0.30)
        sim_prob = min(0.99, max(0.01, sim_prob))
        
        expected_loss = sle * sim_prob
        
        results[asset.id] = {
            'risk_score': normalized_score,
            'expected_loss': expected_loss
        }
        
    return results

def solve_knapsack_fallback(names, costs, values, budget):
    """
    Greedy fallback for solving the knapsack problem.
    """
    n = len(costs)
    # Pack items based on value-to-cost ratio
    items = sorted(
        [(values[i] / costs[i] if costs[i] > 0 else float('inf'), costs[i], values[i], i) for i in range(n)],
        reverse=True
    )
    
    total_cost = 0.0
    selected_indices = []
    
    for ratio, cost, value, idx in items:
        if total_cost + cost <= budget:
            total_cost += cost
            selected_indices.append(idx)
            
    return selected_indices

def run_optimization(budget):
    """
    Finds the optimal combination of controls to implement within the budget.
    """
    # 1. Fetch currently active controls and candidate controls
    all_controls = SecurityControl.query.all()
    active_controls = [c for c in all_controls if c.status == 'Active']
    candidate_controls = [c for c in all_controls if c.status != 'Active']
    
    if not candidate_controls:
        return {
            'recommended_control_ids': [],
            'investment_cost': 0.0,
            'risk_reduction_pct': 0.0,
            'roi': 0.0,
            'before': {},
            'after': {}
        }
        
    # Baseline simulation (before investment - current state)
    current_state = {c.id: c.status for c in all_controls}
    before_sim = simulate_system(current_state)
    total_loss_before = sum(r['expected_loss'] for r in before_sim.values())
    avg_risk_before = sum(r['risk_score'] for r in before_sim.values()) / len(before_sim) if before_sim else 0.0
    
    # 2. Calculate the standalone financial value of each candidate control
    costs = []
    values = []
    ctrl_map = []
    
    for ctrl in candidate_controls:
        # Simulate activating just this one control
        sim_state = current_state.copy()
        sim_state[ctrl.id] = 'Active'
        
        sim_results = simulate_system(sim_state)
        total_loss_sim = sum(r['expected_loss'] for r in sim_results.values())
        
        # Financial reduction (value saved)
        reduction = max(0.0, total_loss_before - total_loss_sim)
        
        cost = ctrl.implementation_cost + ctrl.maintenance_cost
        
        costs.append(cost)
        values.append(reduction)
        ctrl_map.append(ctrl)
        
    # 3. Solve using PuLP
    selected_indices = []
    pulp_success = False
    
    try:
        # Define the problem
        prob = pulp.LpProblem("CyberRisk_Investment_Optimization", pulp.LpMaximize)
        
        # Binary variables for each candidate control
        x = [pulp.LpVariable(f"x_{i}", cat='Binary') for i in range(len(candidate_controls))]
        
        # Objective: Maximize total risk reduction value
        prob += pulp.lpSum(x[i] * values[i] for i in range(len(candidate_controls)))
        
        # Constraint: Budget
        prob += pulp.lpSum(x[i] * costs[i] for i in range(len(candidate_controls))) <= budget
        
        # Solve
        status = prob.solve(pulp.PULP_CBC_CMD(msg=False))
        
        if pulp.LpStatus[status] == 'Optimal':
            selected_indices = [i for i in range(len(candidate_controls)) if pulp.value(x[i]) == 1.0]
            pulp_success = True
    except Exception as e:
        print(f"PuLP Optimization failed: {e}. Falling back to greedy knapsack.")
        
    if not pulp_success:
        selected_indices = solve_knapsack_fallback(
            [c.name for c in candidate_controls],
            costs,
            values,
            budget
        )
        
    recommended_controls = [ctrl_map[i] for i in selected_indices]
    investment_cost = sum(costs[i] for i in selected_indices)
    
    # Simulate final system with ALL recommended controls activated
    final_state = current_state.copy()
    for ctrl in recommended_controls:
        final_state[ctrl.id] = 'Active'
        
    after_sim = simulate_system(final_state)
    total_loss_after = sum(r['expected_loss'] for r in after_sim.values())
    avg_risk_after = sum(r['risk_score'] for r in after_sim.values()) / len(after_sim) if after_sim else 0.0
    
    # Metrics
    loss_reduction = max(0.0, total_loss_before - total_loss_after)
    risk_reduction_pct = (loss_reduction / total_loss_before * 100.0) if total_loss_before > 0 else 0.0
    
    roi = ((loss_reduction - investment_cost) / investment_cost * 100.0) if investment_cost > 0 else 0.0
    
    # Format results
    return {
        'recommended_controls': [c.to_dict() for c in recommended_controls],
        'investment_cost': investment_cost,
        'expected_loss_before': total_loss_before,
        'expected_loss_after': total_loss_after,
        'avg_risk_before': avg_risk_before,
        'avg_risk_after': avg_risk_after,
        'risk_reduction_pct': risk_reduction_pct,
        'roi': roi,
        'before_details': before_sim,
        'after_details': after_sim
    }
