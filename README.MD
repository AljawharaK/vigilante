# Vigilante

**Vigilante** is an Intrusion Detection System (IDS) developed at **King Abdulaziz University** as a Computer Science graduation project. The system combines **Real-Valued Negative Selection (RNSA)** and **K-Nearest Neighbors (KNN)** AI algorithms to detect anomalous network behavior and potential cyber threats.

Designed using the **Waterfall Software Development Life Cycle (SDLC)**, Vigilante integrates machine learning, secure user management, audit logging, and explainable detection capabilities into a unified cybersecurity platform.

## Key Highlights

* AI-powered intrusion detection using **RNSA + KNN**
* Explainable detection results for security analysts
* Role-based access control (Administrator & Analyst)
* Detection analytics, reporting, and audit logging
* PostgreSQL-backed secure data storage
* Multi-factor authentication using OTP verification
* Interactive CLI and GUI dashboard interface
* Research-oriented architecture for cybersecurity experimentation

## Technology Stack

| Category                | Technologies                |
| ----------------------- | --------------------------- |
| Programming             | Python                      |
| Machine Learning        | Scikit-learn, NumPy, Pandas |
| Database                | PostgreSQL                  |
| Authentication          | OTP Verification            |
| Email Services          | Resend API                  |
| Interface               | Argparse CLI, Flet GUI      |
| Reporting               | PDF & CSV Export            |
| Development Methodology | Waterfall SDLC              |

## Architecture

1. User Authentication & Authorization
2. Model Training (RNSA + KNN)
3. Network Traffic Analysis
4. Intrusion Detection & Classification
5. Explainable AI Insights
6. Reporting & Audit Logging

## Research Contribution

Vigilante explores the effectiveness of combining **Artificial Immune System concepts (Real-Valued Negative Selection)** with **Machine Learning classification (KNN)** for anomaly-based intrusion detection based on Li et al. with the paper: Generating detectors from anomaly samples via negative selection for network intrusion detection. The project demonstrates how artificial intelligence can improve the identification of unseen network threats while testing operational usability for cybersecurity analysts.

## Intended Users

* Security Analysts
* Cybersecurity Researchers
* Organizations seeking lightweight IDS experimentation platforms

## Installation

You ethier can use pipx that is used to install and run Python applications in isolated environments or install locally.

```bash
# Install via pipx (recommended)
python -m pip install --user pipx 
pipx install git+https://github.com/AljawharaK/vigilante


# Or install locally
# Create a fresh directory for testing
mkdir vigilante-test
cd vigilante-test

# Copy all your files to maintain the same structure
cp -r "your vigilante-test dir"

# Install dependencies in a virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

pip install -r requirements.txt

# Now run the CLI directly
python -m intrusion_detection.cli --help
```
## Role Permissions

### Administrator Role
- **Full System Access**: Complete control over all system functions
- **User Management**: Create, modify, and deactivate users
- **Audit Logs**: View and export all system activity logs
- **System Reports**: Generate comprehensive PDF reports
- **Model Management**: Full access to all models
- **Detection & Analysis**: All detection, training, and analysis capabilities

### Analyst Role
- **Model Training**: Train new intrusion detection models
- **Anomaly Detection**: Run detection on network traffic
- **Detection Summaries**: View aggregated results and trends
- **AI Explanations**: Generate explanations for detection results
- **Limited to Own Data**: Can only access their own models and detections

### Example Commands
```bash
# Login and enter user name and OTP code
vigilante login
vigilante logout
vigilante --version
vigilante reset-pass
vigilante status
vigilante explain --detection-id 1
vigilante -v or vigilante --verbose
vigilante -h
vigilante [command] --help # There is a help message to every command (train, detect, etc..)
vigilante uninstall --force

# Interactive GUI dashboard for both users
vigilante interactive-gui
# Change the port of Interactive GUI
vigilante interactive-gui --port 8550

# Administrator user management & system monitoring
# 1. Create analyst users
vigilante admin user-create --username analyst1 --email analyst@company.com --role Analyst
vigilante admin user-modify --username user1 --role Administrator
vigilante admin user-deactivate --username olduser
# 2. Monitor system activity
vigilante admin audit-logs --period 7d --output audit_log.csv
vigilante admin system-report --period 30d --output monthly_report.pdf

# Analyst Detection & Analysis
# 1. Train a model on your dataset
vigilante train --input training_data.csv --model-name "Network Traffic Model"
vigilante train --input training_data.csv --model-name "Network Traffic Model" --features "Flow Duration,Fwd Packets,Bwd Packets"

# 2. List available models to get the ID
vigilante list-models
# 3. Run detection on new traffic
vigilante detect --input new_traffic.csv --model-id 1 --threshold 0.6 --output results.json
# 4. Check summary of detections
vigilante summary --period 7d
