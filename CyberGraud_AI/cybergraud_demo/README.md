# CyberGraud AI — Final Runnable Demo

CyberGraud is a safe, gamified cybersecurity platform demonstrating the complete workflow from the supplied project flowchart:

1. User Login & Role-based Dashboard
2. Safe Attack Simulation (synthetic SQL Injection, XSS, Brute Force, DDoS and Normal traffic)
3. Data Collection / telemetry generation
4. AI Threat Detection using Random Forest
5. Explainable AI (transparent feature-influence explanation)
6. Preventive Recommendation Engine
7. Dashboard & Visualization
8. PDF Security Reports + CSV export
9. Security Knowledge Base
10. Admin Control Center

It also includes the integrated **Website Security Analyzer** using the **same AI engine**. The analyzer accepts security telemetry/configuration supplied by the user; it does not probe or exploit external websites.

## Technology
- Python 3.11+ / 3.12 / 3.13
- FastAPI + Uvicorn
- SQLite (zero-configuration demo database; easy to migrate to PostgreSQL later)
- scikit-learn Random Forest
- NumPy / Pandas
- JWT authentication + bcrypt password hashing
- ReportLab PDF generation
- React is not required for this runnable version: the UI uses HTML/CSS/JavaScript so the demo starts with one command. A React frontend can be introduced later without changing the API layer.

## Run on Windows PowerShell

```powershell
cd cybergraud_demo
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open **http://127.0.0.1:8000**.

If PowerShell blocks activation, use:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## Demo users

| Role | Email | Password |
|---|---|---|
| Admin | admin@cybergraud.local | Admin@123 |
| Student | student@cybergraud.local | Student@123 |
| Website Owner | owner@cybergraud.local | Owner@123 |

Change demo passwords before any real deployment.

## Main features

### Gamified Attack Simulation
- Select an attack scenario.
- Synthetic telemetry is generated.
- The Random Forest model predicts normal/malicious activity and attack type.
- Risk is Low / Medium / High.
- Points and badges are awarded.

### Website Security Analyzer
- Enter an application name and telemetry values.
- Uses the same ML model as Gamified Mode.
- Produces prediction, confidence, risk, XAI and recommendations.

### XAI
The demo exposes a transparent feature-influence explanation derived from model feature importance and deviation from a normal baseline. It is designed to show the XAI concept without pretending that a heuristic is a formal SHAP attribution.

### Admin
- View users and roles
- Enable/disable users
- Delete users
- Change roles
- Add/delete knowledge-base entries
- View security/audit activity
- Retrain the Random Forest model and record the run

### Reports
Every detection can be downloaded as a PDF. Users can export their detection history to CSV.

## Database
The database file `cybergraud.db` is created automatically in the project root on first run.

For a final production deployment, migrate the database layer to PostgreSQL and use Redis for real-time queues/caching.

## Safety
This project intentionally uses a controlled/synthetic simulation environment. It does not send attack payloads, scan external websites, perform credential attacks, or launch DDoS traffic.

## Suggested final-project upgrades
- React + TypeScript frontend
- PostgreSQL + Redis
- WebSocket live alerts
- SHAP/LIME visual explanations after validating the dependency stack
- Dataset upload and model-version management
- Docker deployment
- Email verification/notification provider
- Role-specific permissions and organization/tenant support
