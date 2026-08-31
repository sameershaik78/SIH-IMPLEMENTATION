import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import joblib

def generate_synthetic_data(num_samples=500):
    np.random.seed(42)
    
    # 1. cvss_score (0 to 10)
    cvss = np.random.uniform(0.0, 10.0, num_samples)
    
    # 2. asset_criticality (1 to 4)
    crit = np.random.randint(1, 5, num_samples)
    
    # 3. asset_value (log10 of actual value, e.g., 100 to 1,000,000,000 -> 2 to 9)
    val = np.random.uniform(2.0, 9.0, num_samples)
    
    # 4. threat_frequency (0 to 15)
    threat_freq = np.random.uniform(0.0, 15.0, num_samples)
    
    # 5. threat_severity (0 to 4)
    threat_sev = np.random.randint(0, 5, num_samples)
    
    # 6. exploitability (0.1 to 3.0)
    expl = np.random.uniform(0.1, 3.0, num_samples)
    
    # 7. internet_exposure (0 or 1)
    exp = np.random.randint(0, 2, num_samples)
    
    # 8. patch_status (0 or 1)
    patch = np.random.randint(0, 2, num_samples)
    
    # 9. control_effectiveness (0.0 to 1.0)
    ctrl_eff = np.random.uniform(0.0, 1.0, num_samples)
    
    # 10. historical_incidents (0 to 10)
    hist_incidents = np.random.randint(0, 11, num_samples)
    
    # 11. attack_surface (1 to 5)
    surface = np.random.randint(1, 6, num_samples)
    
    # Create DataFrame
    df = pd.DataFrame({
        'cvss_score': cvss,
        'asset_criticality': crit,
        'asset_value': val,
        'threat_frequency': threat_freq,
        'threat_severity': threat_sev,
        'exploitability': expl,
        'internet_exposure': exp,
        'patch_status': patch,
        'control_effectiveness': ctrl_eff,
        'historical_incidents': hist_incidents,
        'attack_surface': surface
    })
    
    # Define incident probability based on logical rules
    prob = (
        0.20 * (cvss / 10.0) +
        0.15 * (crit / 4.0) +
        0.15 * exp +
        0.10 * (threat_sev / 4.0) +
        0.10 * (expl / 3.0) +
        0.10 * (threat_freq / 15.0) +
        0.10 * (surface / 5.0) -
        0.25 * ctrl_eff -
        0.15 * patch
    )
    
    # Add random noise
    prob += np.random.uniform(-0.1, 0.1, num_samples)
    
    # Normalize probabilities to [0, 1]
    prob = np.clip(prob, 0.0, 1.0)
    
    # Class label: 1 if prob > 0.45 else 0
    df['incident_occurred'] = (prob > 0.45).astype(int)
    
    return df

def train_and_save():
    print("Generating synthetic security dataset...")
    df = generate_synthetic_data(800)
    
    X = df.drop(columns=['incident_occurred'])
    y = df['incident_occurred']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_prob)
    
    print(f"Evaluation Metrics:")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1 Score:  {f1:.4f}")
    print(f"  ROC-AUC:   {roc_auc:.4f}")
    
    # Save model and metrics
    output_dir = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(output_dir, exist_ok=True)
    model_path = os.path.join(output_dir, 'model.pkl')
    
    model_data = {
        'model': model,
        'metrics': {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'roc_auc': float(roc_auc)
        },
        'feature_names': list(X.columns)
    }
    
    joblib.dump(model_data, model_path)
    print(f"Model and metrics saved successfully to {model_path}!")

if __name__ == '__main__':
    train_and_save()
