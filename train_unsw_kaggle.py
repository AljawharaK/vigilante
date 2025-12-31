#!/usr/bin/env python3
"""One-time script to train enhanced DCA+Denoising Autoencoder on UNSW-NB15 from Kaggle"""

import sys
import os
import json
import kagglehub
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

# Add the intrusion_detection package to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from intrusion_detection.database import DatabaseManager
from intrusion_detection.auth import AuthManager

# ========================
# 1. Enhanced Denoising Autoencoder
# ========================
class DenoisingAutoencoder(nn.Module):
    def __init__(self, input_dim, encoding_dim=32, noise_factor=0.1):
        super(DenoisingAutoencoder, self).__init__()
        self.noise_factor = noise_factor
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim

        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, encoding_dim),
            nn.BatchNorm1d(encoding_dim),
            nn.ReLU()
        )

        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(encoding_dim, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, input_dim),
            nn.Sigmoid()
        )

    def add_noise(self, x):
        noise = torch.randn_like(x) * self.noise_factor
        return torch.clamp(x + noise, 0, 1)

    def forward(self, x):
        noisy_x = self.add_noise(x)
        encoded = self.encoder(noisy_x)
        decoded = self.decoder(encoded)
        return encoded, decoded

    def encode(self, x):
        with torch.no_grad():
            return self.encoder(x)

    def get_reconstruction_error(self, x):
        with torch.no_grad():
            encoded, decoded = self.forward(x)
            reconstruction_error = torch.mean((x - decoded) ** 2, dim=1).cpu()
        return reconstruction_error.numpy()

# ========================
# 2. DCA Implementation
# ========================
class Antigen:
    def __init__(self, antigen_id: str):
        self._id = antigen_id

    def get_id(self) -> str:
        return self._id

class DendriticCell:
    def __init__(self, migration_threshold: float, max_antigens: int):
        self._migration_threshold = migration_threshold
        self._max_antigens = max_antigens
        self._antigen_store = []
        self._signals = np.zeros(3, dtype=np.float64)
        self._csm = 0.0
        self._k = 0.0

    def phagocytose(self, antigen: Antigen) -> bool:
        if len(self._antigen_store) < self._max_antigens:
            self._antigen_store.append(antigen)
            return True
        return False

    def signal_update(self, signal_vector: np.ndarray):
        self._signals += signal_vector
        # Simplified signal processing
        weights = np.array([[0.7, 0.8, 0.2], [0.6, 0.7, 0.3]])
        outputs = weights.dot(self._signals)
        self._csm = outputs[0]
        self._k = outputs[1]

    def should_migrate(self) -> bool:
        return self._csm >= self._migration_threshold

    def reset(self):
        self._antigen_store = []
        self._signals = np.zeros(3, dtype=np.float64)
        self._csm = 0.0
        self._k = 0.0

# ========================
# 3. Main Training Function
# ========================
def train_enhanced_model():
    """Train the enhanced DCA + Denoising Autoencoder on UNSW-NB15"""
    
    print("=" * 70)
    print("🚀 ENHANCED UNSW-NB15 MODEL TRAINING")
    print("Model: DCA + Denoising Autoencoder")
    print("Dataset: UNSW-NB15 (from Kaggle)")
    print("=" * 70)
    
    # ========================
    # Database Connection
    # ========================
    print("\n🔌 Connecting to database...")
    db = DatabaseManager()
    auth = AuthManager(db)
    
    # Login or register
    print("\n🔐 Authenticating...")
    login_result = auth.login("test", "test123")
    if not login_result['success']:
        print("📝 User not found, registering...")
        register_result = auth.register("test", "test123", "test@example.com")
        if not register_result['success']:
            print(f"❌ Registration failed: {register_result['message']}")
            db.close()
            return
        print("✅ User registered successfully")
    else:
        print(f"✅ Logged in as: {auth.current_user['username']}")
    
    # ========================
    # Download Dataset from Kaggle
    # ========================
    print("\n📥 Downloading UNSW-NB15 dataset from Kaggle...")
    try:
        path = kagglehub.dataset_download("mrwellsdavid/unsw-nb15")
        print(f"✅ Dataset downloaded to: {path}")
        
        train_path = os.path.join(path, "UNSW_NB15_training-set.csv")
        test_path = os.path.join(path, "UNSW_NB15_testing-set.csv")
        
        if not os.path.exists(train_path) or not os.path.exists(test_path):
            print("❌ Dataset files not found!")
            db.close()
            return
            
    except Exception as e:
        print(f"❌ Kaggle dataset download failed: {e}")
        print("Make sure you have kagglehub installed and authenticated")
        db.close()
        return
    
    # ========================
    # Load and Prepare Data
    # ========================
    print("\n📊 Loading dataset...")
    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)
    
    print(f"   Training set: {df_train.shape}")
    print(f"   Testing set: {df_test.shape}")
    
    # Define features (same as your code)
    signal_features = {
        "pamp": ["rate", "sload", "dload"],
        "danger": ["spkts", "dpkts", "sbytes", "dbytes"],
        "safe": ["dur", "sinpkt", "dinpkt"]
    }
    
    all_features = (
        signal_features["pamp"] +
        signal_features["danger"] +
        signal_features["safe"]
    )
    
    # Feature engineering
    print("🔧 Engineering features...")
    def create_engineered_features(df):
        df_engineered = df.copy()
        
        # Traffic ratio features
        if 'sbytes' in df.columns and 'dbytes' in df.columns:
            df_engineered['bytes_ratio'] = df['sbytes'] / (df['dbytes'] + 1)
            df_engineered['bytes_diff'] = abs(df['sbytes'] - df['dbytes'])
        
        # Packet ratio features
        if 'spkts' in df.columns and 'dpkts' in df.columns:
            df_engineered['pkts_ratio'] = df['spkts'] / (df['dpkts'] + 1)
            df_engineered['total_pkts'] = df['spkts'] + df['dpkts']
        
        # Rate-based features
        if 'rate' in df.columns:
            df_engineered['rate_log'] = np.log1p(abs(df['rate']))
        
        # Duration-based features
        if 'dur' in df.columns:
            df_engineered['dur_log'] = np.log1p(abs(df['dur']))
        
        # Load-based features
        if 'sload' in df.columns and 'dload' in df.columns:
            df_engineered['load_ratio'] = df['sload'] / (df['dload'] + 1)
            df_engineered['total_load'] = df['sload'] + df['dload']
        
        return df_engineered
    
    df_train = create_engineered_features(df_train)
    df_test = create_engineered_features(df_test)
    
    # Update feature lists with engineered features
    signal_features["pamp"].extend(['bytes_ratio', 'load_ratio', 'rate_log'])
    signal_features["danger"].extend(['bytes_diff', 'total_pkts', 'total_load'])
    signal_features["safe"].extend(['dur_log', 'pkts_ratio'])
    
    all_features = (
        signal_features["pamp"] +
        signal_features["danger"] +
        signal_features["safe"]
    )
    
    print(f"✅ Total features: {len(all_features)}")
    
    # Prepare data
    X_train_raw = df_train[all_features].copy()
    y_train = df_train["label"].values
    X_test_raw = df_test[all_features].copy()
    y_test = df_test["label"].values
    
    # Handle missing/infinite values
    X_train_raw = X_train_raw.fillna(0).replace([np.inf, -np.inf], 0)
    X_test_raw = X_test_raw.fillna(0).replace([np.inf, -np.inf], 0)
    
    # Scale features
    scaler = MinMaxScaler()
    X_train_scaled = scaler.fit_transform(X_train_raw)
    X_test_scaled = scaler.transform(X_test_raw)
    
    print(f"✅ Data prepared:")
    print(f"   Training shape: {X_train_scaled.shape}")
    print(f"   Testing shape: {X_test_scaled.shape}")
    
    # ========================
    # Train Autoencoder
    # ========================
    print("\n🤖 Training Denoising Autoencoder...")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"   Using device: {device}")
    
    # Create autoencoder
    input_dim = X_train_scaled.shape[1]
    autoencoder = DenoisingAutoencoder(
        input_dim=input_dim,
        encoding_dim=32,
        noise_factor=0.15
    ).to(device)
    
    # Training setup
    X_train_tensor = torch.FloatTensor(X_train_scaled).to(device)
    X_test_tensor = torch.FloatTensor(X_test_scaled).to(device)
    
    criterion = nn.MSELoss()
    optimizer = optim.Adam(autoencoder.parameters(), lr=1e-3)
    
    # Training loop
    autoencoder.train()
    train_losses = []
    epochs = 50
    
    for epoch in range(epochs):
        optimizer.zero_grad()
        _, decoded = autoencoder(X_train_tensor)
        loss = criterion(decoded, X_train_tensor)
        loss.backward()
        optimizer.step()
        
        train_losses.append(loss.item())
        
        if (epoch + 1) % 10 == 0:
            print(f"   Epoch {epoch + 1}/{epochs}, Loss: {loss.item():.6f}")
    
    print(f"✅ Autoencoder trained with final loss: {train_losses[-1]:.6f}")
    
    # ========================
    # DCA Processing
    # ========================
    print("\n🛡️  Processing through DCA...")
    
    # Get reconstruction errors
    autoencoder.eval()
    train_errors = autoencoder.get_reconstruction_error(X_train_tensor)
    test_errors = autoencoder.get_reconstruction_error(X_test_tensor)
    
    # Set anomaly threshold (95th percentile)
    threshold = np.percentile(train_errors, 95)
    print(f"   Anomaly threshold: {threshold:.6f}")
    
    # Initialize DCA population
    population_size = 100
    migration_range = (0.5, 1.5)
    max_antigens = 10
    
    population = []
    for _ in range(population_size):
        mt = np.random.uniform(migration_range[0], migration_range[1])
        population.append(DendriticCell(mt, max_antigens))
    
    # Process test data through DCA
    def compute_signals(features, recon_error):
        """Compute PAMP, DANGER, SAFE signals"""
        # Simplified signal computation based on features
        pamp = np.mean(features[:3]) * (1 + recon_error * 0.5)
        danger = np.mean(features[3:7]) * (1 + recon_error * 0.8)
        safe = np.mean(features[7:]) * (1 - recon_error * 0.3)
        return np.array([pamp, danger, safe], dtype=np.float64)
    
    # Track antigen presentations
    antigen_profiles = {}
    anomalies_detected = []
    
    for i in range(len(X_test_scaled)):
        antigen_id = f"test_{i}"
        signals = compute_signals(X_test_scaled[i], test_errors[i])
        
        # Sample to a DC
        dc = population[i % population_size]
        antigen = Antigen(antigen_id)
        dc.phagocytose(antigen)
        dc.signal_update(signals)
        
        # Track antigen
        if antigen_id not in antigen_profiles:
            antigen_profiles[antigen_id] = {
                'presentations': 0,
                'anomaly_presentations': 0
            }
        
        # Determine if anomaly (simplified)
        anomaly_score = (signals[0] + signals[1] - signals[2]) / 3.0
        is_anomaly = anomaly_score > 0.5 or test_errors[i] > threshold
        
        if is_anomaly:
            antigen_profiles[antigen_id]['anomaly_presentations'] += 1
            if antigen_id not in anomalies_detected:
                anomalies_detected.append(antigen_id)
        
        antigen_profiles[antigen_id]['presentations'] += 1
        
        # Check for migration
        if dc.should_migrate():
            dc.reset()
    
    print(f"✅ DCA processing complete")
    print(f"   Antigens processed: {len(antigen_profiles)}")
    print(f"   Anomalies detected: {len(anomalies_detected)}")
    
    # ========================
    # Evaluate Model
    # ========================
    print("\n📈 Evaluating model performance...")
    
    # Combined predictions (Autoencoder + DCA)
    ae_predictions = (test_errors > threshold).astype(int)
    
    # DCA predictions
    dca_predictions = np.zeros(len(y_test), dtype=int)
    for anomaly in anomalies_detected:
        idx = int(anomaly.split('_')[1])
        if idx < len(dca_predictions):
            dca_predictions[idx] = 1
    
    # Combined predictions (OR logic)
    final_predictions = ((ae_predictions + dca_predictions) >= 1).astype(int)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, final_predictions)
    precision = precision_score(y_test, final_predictions, zero_division=0)
    recall = recall_score(y_test, final_predictions, zero_division=0)
    f1 = f1_score(y_test, final_predictions, zero_division=0)
    cm = confusion_matrix(y_test, final_predictions)
    
    print(f"✅ Evaluation complete:")
    print(f"   Accuracy:  {accuracy:.4f}")
    print(f"   Precision: {precision:.4f}")
    print(f"   Recall:    {recall:.4f}")
    print(f"   F1-Score:  {f1:.4f}")
    print(f"   Confusion Matrix:")
    print(f"     TN: {cm[0,0]}, FP: {cm[0,1]}")
    print(f"     FN: {cm[1,0]}, TP: {cm[1,1]}")
    
    # ========================
    # Save to Database
    # ========================
    print("\n💾 Saving model...")
    
    # Create model directory
    model_name = "test-model"
    model_dir = os.path.join("models", model_name)
    os.makedirs(model_dir, exist_ok=True)
    
    # Save autoencoder
    ae_path = os.path.join(model_dir, "autoencoder.pth")
    torch.save({
        'model_state_dict': autoencoder.state_dict(),
        'input_dim': input_dim,
        'encoding_dim': 32,
        'noise_factor': 0.15
    }, ae_path)
    
    # Save scaler
    scaler_path = os.path.join(model_dir, "scaler.joblib")
    import joblib
    joblib.dump(scaler, scaler_path)
    
    # Save DCA parameters
    dca_params = {
        'population_size': population_size,
        'migration_range': migration_range,
        'max_antigens': max_antigens,
        'threshold': float(threshold),
        'feature_names': all_features,
        'antigen_profiles': antigen_profiles
    }
    dca_path = os.path.join(model_dir, "dca_params.joblib")
    joblib.dump(dca_params, dca_path)
    
    # Save metadata
    metadata = {
        'model_name': model_name,
        'created_at': pd.Timestamp.now().isoformat(),
        'dataset': 'UNSW-NB15',
        'dataset_source': 'kagglehub/mrwellsdavid/unsw-nb15',
        'training_samples': len(X_train_scaled),
        'test_samples': len(X_test_scaled),
        'features_count': input_dim,
        'metrics': {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'threshold': float(threshold),
            'anomalies_detected': len(anomalies_detected),
            'anomaly_rate': float(len(anomalies_detected) / len(y_test))
        },
        'parameters': {
            'autoencoder_encoding_dim': 32,
            'autoencoder_noise_factor': 0.15,
            'dca_population_size': population_size,
            'training_epochs': epochs,
            'learning_rate': 1e-3
        }
    }
    
    user = auth.get_current_user()
    
    try:
        model_id = db.save_model(
            user_id=user['id'],
            model_name=model_name,
            model_path=model_dir,
            metrics=metadata['metrics'],
            parameters=metadata['parameters']
        )
        
        print(f"✅ Model saved to database with ID: {model_id}")
        
        # Verify
        db_model = db.get_model(model_id, user['id'])
        if db_model:
            print(f"\n📋 Database Model Details:")
            print(f"   ID: {db_model['id']}")
            print(f"   Name: {db_model['name']}")
            print(f"   Accuracy: {db_model['accuracy']:.2%}")
            print(f"   Created: {db_model['created_at']}")
            print(f"   Path: {db_model['model_path']}")
            
    except Exception as e:
        print(f"❌ Error saving to database: {e}")
    
    # ========================
    # Summary
    # ========================
    print("\n" + "=" * 70)
    print("🎉 TRAINING COMPLETE!")
    print("=" * 70)
    print(f"\n📊 Model Performance:")
    print(f"   Accuracy:  {accuracy:.2%}")
    print(f"   Precision: {precision:.2%}")
    print(f"   Recall:    {recall:.2%}")
    print(f"   F1-Score:  {f1:.2%}")
    print(f"\n📁 Model Location: {model_dir}")
    print(f"\n🚀 Next steps:")
    print(f"   1. Use CLI: ids-cli --list-models")
    print(f"   2. Detect anomalies: ids-cli --detect --model-path {model_dir} --data-file YOUR_DATA.csv")
    print(f"   3. Train more models: ids-cli --train --data-file data.csv --model-name new-model")
    
    # Close database
    db.close()

if __name__ == "__main__":
    train_enhanced_model()