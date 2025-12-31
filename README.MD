# Intrusion Detection CLI Tool

A command-line tool for intrusion detection using Deterministic DCA + Denoising Autoencoder.

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