# CyberRisk AI — AI-Powered Continuous Cyber Risk Quantification and Investment Optimization Platform

CyberRisk AI is a professional, production-style full-stack cybersecurity platform designed to continuously quantify an organization's cyber risk in financial terms (Indian Rupees ₹), evaluate defensive controls, and intelligently optimize security investments under budget constraints.

## Project Objectives & Problem Solved
Security teams struggle to translate technical vulnerabilities (like CVSS scores) into business metrics. C-Suite executives ask:
> **“What are our most important cyber risks, how much could they cost us, and where should we invest our cybersecurity budget to achieve the maximum risk reduction?”**

**CyberRisk AI** answers this by mapping CVEs, threats, and assets to Single Loss Expectancy (SLE), Annualized Loss Expectancy (ALE), and using a **Random Forest Classifier** to predict the probability of security incidents. It then runs a binary knapsack optimization solver (`PuLP`) to recommend the best combination of security controls within a specified budget to maximize ROI.

---

## 1. System Architecture

```text
CyberRisk AI
│
├── Data Sources (CVE/CVSS, CISA KEV, Threat Intel, Assets, Incidents)
│
├── Data Processing Layer (Flask-SQLAlchemy Models)
│
├── AI/ML Risk Engine (Random Forest Incident Probability Predictor)
│
├── Financial Risk Engine (SLE, ARO, ALE, Expected Loss in INR ₹)
│
├── Investment Optimization Engine (PuLP constrained optimization)
│
├── Continuous Monitoring & Alerting (Auto recalculate on updates + Threshold flags)
│
├── REST API Layer (Clean JSON Endpoints)
│
└── Web Dashboard (Dark SOC Theme with Chart.js & Risk Heatmap)
```

---

## 2. Technology Stack
* **Frontend**: HTML5, CSS3, JavaScript (ES6), Bootstrap 5 (Dark SOC custom theme), Chart.js, Font Awesome.
* **Backend**: Python 3.11+, Flask (REST APIs), Flask-CORS, Flask-SQLAlchemy.
* **Database**: SQLite (SQLAlchemy ORM - PostgreSQL compatible).
* **Data Science / ML**: Pandas, NumPy, Scikit-learn, Joblib.
* **Optimization**: PuLP (Linear Programming Solver).

---

## 3. Installation & Setup

Follow these exact steps to run the application locally on Windows:

### Step 1: Clone or Enter Project Directory
Open PowerShell or Command Prompt in the project folder:
```bash
cd "c:\Users\user\Downloads\SIH IMPLEMENTATION"
```

### Step 2: Create and Activate Virtual Environment
```bash
python -m venv venv
venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Step 4: Train the Machine Learning Model
Generate the synthetic historical incident dataset and compile the Random Forest classifier:
```bash
python ml/train_model.py
```

### Step 5: Seed the Database
Initialize the SQLite schema, load 20 assets, 10 controls, 30 vulnerabilities, 15 threats, 20 incidents, and compute the starting state:
```bash
python seed_data.py
```

### Step 6: Run the Platform
Start the Flask development server:
```bash
python app.py
```

Open your web browser and navigate to: **`http://localhost:5000`**

---

## 4. Environment Variables (`.env.example`)
Create a `.env` file in the root directory if you wish to override defaults:
```text
SECRET_KEY=cyberrisk-ai-super-secret-key-12345
DATABASE_URL=sqlite:///cyberrisk.db
FLASK_DEBUG=True
PORT=5000
```

---

## 5. Main APIs

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/login` | Authenticate username and password |
| GET | `/api/dashboard` | Fetch KPI stats, risk distribution, and ML model details |
| GET | `/api/assets` | Retrieve list of assets with active risk scores and expected loss |
| POST | `/api/assets` | Add a new asset (triggers auto-recalculation) |
| GET | `/api/vulnerabilities` | Retrieve vulnerabilities list |
| PUT | `/api/vulnerabilities/<id>` | Toggle patch status (triggers auto-recalculation) |
| GET | `/api/risks/<asset_id>` | Return detailed risk factors, incident probability, and mitigations |
| POST | `/api/optimize` | Run budget optimizer and return recommended controls, ROI, and comparisons |
| GET | `/api/alerts` | Get active warning flags |
| POST | `/api/recalculate-risk` | Manually run risk/financial quantification across all assets |
| POST | `/api/train-ml` | Trigger Random Forest model retraining |

---

## 6. SIH Live Demo Workflow

Demonstrate the core platform capabilities during the evaluation:

1. **Sign In**: Access the login page and authenticate as an analyst:
   * **Username**: `analyst`
   * **Password**: `password123`
2. **Explore SOC Dashboard**:
   * Review overall **Risk Score** and **Expected Annual Loss** (formatted in Indian Rupees ₹).
   * Inspect the **Risk Heatmap** (interactive Likelihood vs Impact grid) and click on assets to jump to their risk details.
   * View the **ML Model Performance Metrics** at the bottom.
3. **Analyze Asset Risk Detail**:
   * Navigate to **Risk Analysis** page. Click on `Payment Gateway API` or `Customer Database`.
   * Explain the **AI Risk Diagnostics** bullet points which explain why the asset is high risk (e.g. unpatched CVSS 9.8, internet exposed, critical business dependency).
   * Show the progress bars of contributing factors.
4. **Optimize Cybersecurity Budget**:
   * Open the **Investment Optimizer** page.
   * Enter a budget: **`₹10,00,000`** (default).
   * Click **Optimize Security Budget**.
   * Show the **Before vs After** charts updating instantly:
     * Average Risk Score drops.
     * Expected Loss Exposure is cut down.
   * Show the recommended list of controls (e.g., MFA, EDR, Backups) that fit within the budget and show the **Return on Investment (ROI)**.
5. **Simulate Continuous Monitoring**:
   * Navigate to **Vulnerabilities** page.
   * Find critical unpatched CVEs on `Payment Gateway API` (`CVE-2023-3519` with CVSS 9.8) and check the **Patch Status** toggle.
   * Toggle it to **Patched**.
   * Return to the **Dashboard** or **Risk Analysis** and show that the overall risk score and expected financial loss have dropped immediately.
   * Navigate to **Alerts** to see that the critical vulnerability alert is resolved.
