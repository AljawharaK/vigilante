# Intrusion Detection CLI Tool

A command-line tool for intrusion detection using RNSA + KNN.

## Features
- User authentication and management
- Train new intrusion detection models
- Load and use pre-trained models
- Detect anomalies in uploaded data
- Store models and user data in PostgreSQL
- Interactive CLI with rich interface

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
vigilante explain (without --detection-id for file input)
vigilante -v or vigilante --verbose
vigilante -h
vigilante --help

# Administrator user management & system monitoring
# 1. Create analyst users
vigilante admin user-create --username analyst1 --email analyst@company.com --role Analyst
vigilante admin user-modify --username user1 --role Administrator
vigilante admin user-deactivate --username olduser
# 2. Monitor system activity
vigilante admin audit-logs --period 7d
vigilante admin system-report --period 30d --output monthly_report.pdf

# Analyst Detection & Analysis
# 1. Train a model on your dataset
vigilante train --input training_data.csv --model-name "Network Traffic Model"
# 2. List available models to get the ID
vigilante list-models
# 3. Run detection on new traffic
vigilante detect --input new_traffic.csv --model-id 1 --explain --output results.json
# 4. Check summary of detections
vigilante summary --period 7d
