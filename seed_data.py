import os
from datetime import datetime, timedelta
from app import create_app
from database import db
from models.user import User
from models.asset import Asset
from models.security_control import SecurityControl
from models.vulnerability import Vulnerability
from models.threat import Threat
from models.incident import Incident
from services.risk_engine import run_risk_engine
from services.financial_model import run_financial_model
from services.alert_service import evaluate_alerts

def seed():
    app = create_app()
    with app.app_context():
        print("Dropping existing tables...")
        db.drop_all()
        print("Creating new tables...")
        db.create_all()

        # 1. Seed Users
        print("Seeding Users...")
        admin = User(username='admin', role='Admin')
        admin.set_password('password123')
        
        analyst = User(username='analyst', role='Security Analyst')
        analyst.set_password('password123')
        
        executive = User(username='executive', role='Executive')
        executive.set_password('password123')
        
        db.session.add_all([admin, analyst, executive])
        db.session.commit()

        # 2. Seed Security Controls (10 controls)
        print("Seeding Security Controls...")
        controls = [
            SecurityControl(
                name='Multi-Factor Authentication (MFA)', category='Identity',
                implementation_cost=250000, maintenance_cost=100000,
                effectiveness=95.0, coverage=85.0, status='Active',
                risk_reduction_factor=90.0, description='Enforces MFA for all user logins, reducing credential theft risk.'
            ),
            SecurityControl(
                name='Next-Gen Firewall (NGFW)', category='Network',
                implementation_cost=400000, maintenance_cost=150000,
                effectiveness=90.0, coverage=95.0, status='Active',
                risk_reduction_factor=85.0, description='Deep packet inspection firewall to filter network threats.'
            ),
            SecurityControl(
                name='Endpoint Detection & Response (EDR)', category='Endpoint',
                implementation_cost=350000, maintenance_cost=120000,
                effectiveness=88.0, coverage=80.0, status='Active',
                risk_reduction_factor=80.0, description='Continuous monitoring of host endpoints for malicious behaviors.'
            ),
            SecurityControl(
                name='Data Loss Prevention (DLP)', category='Data',
                implementation_cost=600000, maintenance_cost=200000,
                effectiveness=75.0, coverage=30.0, status='Inactive',
                risk_reduction_factor=70.0, description='Identifies, monitors, and blocks sensitive data transfers.'
            ),
            SecurityControl(
                name='Security Information & Event Management (SIEM)', category='Operations',
                implementation_cost=800000, maintenance_cost=300000,
                effectiveness=85.0, coverage=70.0, status='Active',
                risk_reduction_factor=75.0, description='Centralized log management and correlation for real-time alerting.'
            ),
            SecurityControl(
                name='Automated Database Backup & DR', category='Data',
                implementation_cost=500000, maintenance_cost=250000,
                effectiveness=98.0, coverage=90.0, status='Active',
                risk_reduction_factor=95.0, description='Automated, encrypted off-site backups with rapid recovery testing.'
            ),
            SecurityControl(
                name='Zero Trust Network Access (ZTNA)', category='Network',
                implementation_cost=1200000, maintenance_cost=400000,
                effectiveness=92.0, coverage=20.0, status='Proposed',
                risk_reduction_factor=90.0, description='Adaptive trust model restricting system access on a strict need-to-know basis.'
            ),
            SecurityControl(
                name='Security Awareness Training', category='Awareness',
                implementation_cost=150000, maintenance_cost=50000,
                effectiveness=70.0, coverage=90.0, status='Active',
                risk_reduction_factor=60.0, description='Regular training of employees on phishing, passwords, and data handling.'
            ),
            SecurityControl(
                name='Vulnerability Management Program', category='Operations',
                implementation_cost=300000, maintenance_cost=100000,
                effectiveness=80.0, coverage=75.0, status='Active',
                risk_reduction_factor=80.0, description='Continuous scanning and formal SLA-backed patching workflows.'
            ),
            SecurityControl(
                name='Database Encryption at Rest', category='Data',
                implementation_cost=450000, maintenance_cost=150000,
                effectiveness=95.0, coverage=40.0, status='Inactive',
                risk_reduction_factor=85.0, description='Encrypts backend database volumes and tables to secure critical records.'
            )
        ]
        
        db.session.add_all(controls)
        db.session.commit()

        # 3. Seed Assets (20 assets)
        print("Seeding Assets...")
        assets_data = [
            # Critical
            ('Customer Database', 'Database', 50000000.0, 'Critical', 'Core business operation', 'PCI-DSS and PII data', False, 'Zone A', 'Data Team'),
            ('Payment Gateway API', 'Web Application', 80000000.0, 'Critical', 'Customer transaction workflow', 'Financial data', True, 'AWS us-east-1', 'Payments Team'),
            ('SCADA Network Controller', 'Network Device', 100000000.0, 'Critical', 'Industrial operations control', 'Highly proprietary', False, 'Facility Zone 1', 'ICS Ops'),
            ('Active Directory Server', 'Server', 35000000.0, 'Critical', 'Identity provider and domain access', 'Credentials and groups', False, 'Zone A', 'Security Ops'),
            ('AWS Cloud Storage S3', 'Cloud Resource', 60000000.0, 'Critical', 'Static database backups and files', 'PII records', True, 'AWS us-west-2', 'Cloud Team'),
            
            # High
            ('Public Web Server', 'Server', 12000000.0, 'High', 'E-commerce website host', 'Client-facing logs', True, 'DMZ 1', 'IT Operations'),
            ('Employee Laptop (CEO)', 'Endpoint', 250000.0, 'High', 'Executive device access', 'Proprietary business plans', True, 'Remote', 'Executive Office'),
            ('Corporate Mail Server', 'Server', 15000000.0, 'High', 'Exchange mail services', 'Internal correspondence', True, 'Zone B', 'IT Operations'),
            ('Corporate Firewall', 'Network Device', 4500000.0, 'High', 'Primary border protection', 'Network flow rules', True, 'DMZ Border', 'Security Ops'),
            ('Finance File Server', 'Server', 20000000.0, 'High', 'Internal payroll and ledgers', 'Tax and accounting details', False, 'Zone A', 'Finance Team'),
            ('Corporate VPN Gateway', 'Network Device', 3000000.0, 'High', 'Remote worker access gateway', 'Internal endpoint routing', True, 'DMZ Border', 'Security Ops'),
            ('CRM Web App', 'Web Application', 10000000.0, 'High', 'Client relationship portal', 'Sales pipelines and accounts', True, 'AWS us-east-1', 'Sales Ops'),
            ('R&D Source Code Repo', 'Cloud Resource', 40000000.0, 'High', 'Software IP repository', 'Source code', False, 'GitHub Enterprise', 'Engineering Team'),
            
            # Medium
            ('HR Portal', 'Web Application', 5000000.0, 'Medium', 'Employee attendance & profile tools', 'Employee records', False, 'Zone B', 'HR Team'),
            ('Developer Workstation 1', 'Endpoint', 150000.0, 'Medium', 'Code building machine', 'Code dependencies', False, 'Zone C', 'Engineering Team'),
            ('Developer Workstation 2', 'Endpoint', 150000.0, 'Medium', 'Code building machine', 'Code dependencies', False, 'Zone C', 'Engineering Team'),
            
            # Low
            ('Internal Wiki', 'Web Application', 1000000.0, 'Low', 'Documentation storage', 'Public internal guides', False, 'Zone C', 'IT Operations'),
            ('CCTV System Controller', 'IoT Device', 2000000.0, 'Low', 'Security camera feeds', 'Camera feeds', True, 'Facility Perimeter', 'Facilities'),
            ('Smart Thermostat Hub', 'IoT Device', 500000.0, 'Low', 'Office temperature monitoring', 'Telemetry logs', True, 'HQ Floor 1', 'Facilities'),
            ('Marketing Web Server', 'Server', 1500000.0, 'Low', 'Corporate campaigns hosting', 'Public content only', True, 'DMZ 2', 'Marketing Team')
        ]
        
        assets_list = []
        for name, atype, val, crit, b_imp, d_sens, ie, loc, owner in assets_data:
            asset = Asset(
                name=name, type=atype, value=val, criticality=crit,
                business_importance=b_imp, data_sensitivity=d_sens,
                internet_exposure=ie, location=loc, owner=owner
            )
            db.session.add(asset)
            assets_list.append(asset)
            
        db.session.commit()
        # Create asset lookup helper
        asset_map = {a.name: a for a in assets_list}

        # 4. Seed Vulnerabilities (30 vulnerabilities)
        print("Seeding Vulnerabilities...")
        vulnerabilities_data = [
            ('CVE-2021-44228', 'Public Web Server', 10.0, 'Critical', 3.0, 'Network', False, True, True),
            ('CVE-2023-3519', 'Payment Gateway API', 9.8, 'Critical', 2.8, 'Network', False, True, True),
            ('CVE-2024-3400', 'Corporate Firewall', 10.0, 'Critical', 3.0, 'Network', False, True, True),
            ('CVE-2022-40684', 'SCADA Network Controller', 9.8, 'Critical', 2.8, 'Network', False, False, False),
            ('CVE-2023-34362', 'AWS Cloud Storage S3', 9.8, 'Critical', 2.8, 'Network', False, True, True),
            ('CVE-2023-20198', 'Corporate VPN Gateway', 10.0, 'Critical', 3.0, 'Network', False, True, True),
            ('CVE-2021-34527', 'Active Directory Server', 8.8, 'High', 2.0, 'Local', False, True, True),
            ('CVE-2024-21626', 'AWS Cloud Storage S3', 8.6, 'High', 2.0, 'Local', False, False, False),
            ('CVE-2023-22518', 'HR Portal', 9.8, 'Critical', 2.8, 'Network', False, False, False),
            ('CVE-2022-22965', 'CRM Web App', 9.8, 'Critical', 2.8, 'Network', False, False, False),
            ('CVE-2023-46604', 'Finance File Server', 10.0, 'Critical', 3.0, 'Network', False, False, False),
            ('CVE-2023-27997', 'Corporate VPN Gateway', 9.8, 'Critical', 2.8, 'Network', False, False, False),
            ('CVE-2021-26855', 'Corporate Mail Server', 9.8, 'Critical', 2.8, 'Network', False, False, False),
            ('CVE-2024-32002', 'R&D Source Code Repo', 9.0, 'Critical', 2.5, 'Network', False, False, False),
            ('CVE-2023-3247', 'Corporate Firewall', 8.6, 'High', 2.0, 'Network', False, False, False),
            ('CVE-2023-3824', 'Marketing Web Server', 9.8, 'Critical', 2.8, 'Network', False, False, False),
            ('CVE-2023-28252', 'Developer Workstation 2', 7.8, 'High', 1.8, 'Local', False, False, False),
            ('CVE-2021-3156', 'Customer Database', 7.8, 'High', 1.8, 'Local', False, False, False),
            ('CVE-2024-23897', 'R&D Source Code Repo', 7.5, 'High', 1.8, 'Network', False, False, False),
            ('CVE-2023-32342', 'CRM Web App', 5.9, 'Medium', 1.2, 'Network', False, False, False),
            ('CVE-2023-49103', 'Internal Wiki', 7.5, 'High', 1.8, 'Network', False, False, False),
            ('CVE-2023-38606', 'Employee Laptop (CEO)', 7.8, 'High', 1.8, 'Local', False, False, False),
            
            # Patched Vulns
            ('CVE-2020-0601', 'Employee Laptop (CEO)', 8.1, 'High', 2.0, 'Local', True, False, False),
            ('CVE-2017-0144', 'Active Directory Server', 8.1, 'High', 2.0, 'Network', True, True, True),
            ('CVE-2020-1472', 'Active Directory Server', 10.0, 'Critical', 3.0, 'Network', True, True, True),
            ('CVE-2023-26360', 'Public Web Server', 9.8, 'Critical', 2.8, 'Network', True, True, True),
            ('CVE-2022-26134', 'HR Portal', 9.8, 'Critical', 2.8, 'Network', True, True, True),
            ('CVE-2022-30190', 'Developer Workstation 1', 7.8, 'High', 1.8, 'Network', True, True, True),
            ('CVE-2019-11510', 'Corporate VPN Gateway', 10.0, 'Critical', 3.0, 'Network', True, True, True),
            ('CVE-2022-1040', 'Corporate Firewall', 9.8, 'Critical', 2.8, 'Network', True, True, True)
        ]
        
        for cve, asset_name, cvss, sev, expl, av, patched, pub, kev in vulnerabilities_data:
            vuln = Vulnerability(
                cve_id=cve, asset_id=asset_map[asset_name].id, cvss_score=cvss,
                severity=sev, exploitability=expl, attack_vector=av,
                patch_status=patched, public_exploit=pub, kev_status=kev
            )
            db.session.add(vuln)
            
        db.session.commit()

        # 5. Seed Threats (15 threats)
        print("Seeding Threats...")
        threats_data = [
            ('APT Ransomware Campaign', 'Ransomware', 'Critical', 3, 4, 'Network', 'LockBit 3.0 actor', 'Customer Database', 'Double extortion targeting customer databases.'),
            ('Spear Phishing Campaign', 'Phishing', 'High', 5, 5, 'Network', 'External Phishing Actor', 'Employee Laptop (CEO)', 'Highly targeted email campaigns to compromise credentials.'),
            ('SQL Injection Attack', 'Web Attack', 'High', 4, 3, 'Network', 'Script Kiddies', 'Payment Gateway API', 'Exploiting API parameter sanitization flaws.'),
            ('DDoS Attack on Web Infrastructure', 'DDoS', 'High', 3, 4, 'Network', 'Botnet Operators', 'Public Web Server', 'Flood traffic aiming to cause web service downtime.'),
            ('Credential Stuffing', 'Credential Theft', 'Medium', 5, 4, 'Network', 'Automated Cybercriminals', 'CRM Web App', 'Reusing credentials leaked from external breaches.'),
            ('Malicious Insider', 'Insider Threat', 'Critical', 2, 2, 'Local', 'Disgruntled Employee', 'R&D Source Code Repo', 'Attempts to copy proprietary codebase or keys.'),
            ('Supply Chain Compromise', 'Supply Chain Attack', 'High', 2, 3, 'Network', 'SaaS Provider Vendor', 'AWS Cloud Storage S3', 'Injecting malicious updates into cloud packages.'),
            ('Active Directory Domain Compromise', 'Malware', 'Critical', 1, 2, 'Local', 'Internal lateral movers', 'Active Directory Server', 'Obtaining Domain Admin to extract the NTDS.dit database.'),
            ('CCTV Botnet Recruitment', 'Malware', 'Low', 4, 4, 'Network', 'Mirai variants', 'CCTV System Controller', 'Scanning IoT ports to install coin miners/DDoS bots.'),
            ('SCADA Exploitation', 'Malware', 'Critical', 1, 2, 'Local', 'State-sponsored threat actors', 'SCADA Network Controller', 'Aimed at disabling physical factory temperature controllers.'),
            ('Mail Server Spoofing', 'Phishing', 'Medium', 4, 3, 'Network', 'Email Scammers', 'Corporate Mail Server', 'Spam and business email compromise tactics.'),
            ('Cloud S3 Bucket Misconfiguration Leak', 'Insider Threat', 'High', 3, 3, 'Network', 'DevOps Analyst', 'AWS Cloud Storage S3', 'Accidental public access configuration of S3 containers.'),
            ('VPN Gateway Exploitation', 'Web Attack', 'Critical', 3, 4, 'Network', 'Recon actors', 'Corporate VPN Gateway', 'Targeting unpatched firmware to establish initial hold.'),
            ('Wi-Fi Eavesdropping', 'Web Attack', 'Low', 3, 2, 'Physical', 'Rogue Access Point', 'Developer Workstation 1', 'Sniffing local unencrypted traffic on workspace floors.'),
            ('Employee Credential Leak', 'Credential Theft', 'High', 4, 3, 'Network', 'Third-party dump', 'HR Portal', 'Employee passwords leaked in unrelated external forums.')
        ]
        
        for name, ttype, sev, freq, like, av, actor, asset_name, desc in threats_data:
            threat = Threat(
                name=name, type=ttype, severity=sev, frequency=freq,
                likelihood=like, attack_vector=av, threat_actor=actor,
                affected_asset_id=asset_map[asset_name].id, description=desc
            )
            db.session.add(threat)
            
        db.session.commit()

        # 6. Seed Incidents (20 incidents)
        print("Seeding Incidents...")
        incidents_data = [
            ('SQL Injection Attempt', 'Payment Gateway API', 'Web Attack', 250000.0, 30),
            ('DDoS Service Outage', 'Public Web Server', 'DDoS', 400000.0, 90),
            ('CEO Credential Phish Attempt', 'Employee Laptop (CEO)', 'Phishing', 50000.0, 15),
            ('Unauthorized SQL Read', 'Customer Database', 'Credential Theft', 1500000.0, 60),
            ('S3 Backup Exposure Incident', 'AWS Cloud Storage S3', 'Leak', 1200000.0, 45),
            ('Worm Spread Event', 'Active Directory Server', 'Malware', 500000.0, 120),
            ('Spam Gateway Overload', 'Corporate Mail Server', 'Phishing', 100000.0, 10),
            ('External SCADA Port Probe', 'SCADA Network Controller', 'Malware', 0.0, 80),
            ('Credential Harvesting Form', 'HR Portal', 'Phishing', 80000.0, 25),
            ('Workstation Adware Infection', 'Developer Workstation 1', 'Malware', 15000.0, 5),
            
            ('Bulk Data Exfiltration Attempt', 'Customer Database', 'Leak', 4500000.0, 8),
            ('API Abuse Event', 'Payment Gateway API', 'Web Attack', 600000.0, 12),
            ('Phishing Mail Delivery', 'Corporate Mail Server', 'Phishing', 20000.0, 2),
            ('Ransomware Test Loader Blocked', 'Employee Laptop (CEO)', 'Ransomware', 100000.0, 14),
            ('Web Shell Upload Attempt', 'Public Web Server', 'Web Attack', 300000.0, 20),
            ('VPN Gateway Brute Force', 'Corporate VPN Gateway', 'Credential Theft', 50000.0, 4),
            ('Corporate Firewall Rules Corrupted', 'Corporate Firewall', 'Web Attack', 200000.0, 6),
            ('Public S3 Data Scraped', 'AWS Cloud Storage S3', 'Leak', 800000.0, 22),
            ('CEO Malware Phish Success', 'Employee Laptop (CEO)', 'Phishing', 750000.0, 3),
            ('Web Server Defaced', 'Public Web Server', 'Web Attack', 150000.0, 1)
        ]
        
        for title, asset_name, itype, cost, days_ago in incidents_data:
            dt = datetime.utcnow() - timedelta(days=days_ago)
            incident = Incident(
                title=title, asset_id=asset_map[asset_name].id, type=itype,
                impact_cost=cost, incident_date=dt, status='Mitigated'
            )
            db.session.add(incident)
            
        db.session.commit()

        # 7. Run Calculations
        print("Calculating initial risk posture...")
        run_risk_engine()
        print("Quantifying financial losses...")
        run_financial_model()
        print("Evaluating system alerts...")
        evaluate_alerts()
        
        print("Database Seeded and initial calculations completed successfully!")

if __name__ == '__main__':
    seed()
