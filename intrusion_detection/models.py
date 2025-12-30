# intrusion_detection/model.py
import os
import torch
import torch.nn as nn
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from typing import Tuple, Dict, Any, Optional

# ========================
# Denoising Autoencoder Definition
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
        """Add Gaussian noise for denoising"""
        noise = torch.randn_like(x) * self.noise_factor
        return torch.clamp(x + noise, 0, 1)

    def forward(self, x):
        # Add noise for denoising
        noisy_x = self.add_noise(x)
        
        # Encode
        encoded = self.encoder(noisy_x)
        
        # Decode
        decoded = self.decoder(encoded)
        
        return encoded, decoded

    def encode(self, x):
        """Get encoded representation without adding noise"""
        with torch.no_grad():
            return self.encoder(x)

    def get_reconstruction_error(self, x):
        """Calculate reconstruction error for each sample"""
        with torch.no_grad():
            encoded, decoded = self.forward(x)
            reconstruction_error = torch.mean((x - decoded) ** 2, dim=1).cpu()
        return reconstruction_error.numpy()

    def save(self, path: str):
        """Save model to file"""
        torch.save({
            'model_state_dict': self.state_dict(),
            'input_dim': self.input_dim,
            'encoding_dim': self.encoding_dim,
            'noise_factor': self.noise_factor
        }, path)
    
    @classmethod
    def load(cls, path: str, device=None):
        """Load model from file"""
        if device is None:
            device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        checkpoint = torch.load(path, map_location=device)
        model = cls(
            input_dim=checkpoint['input_dim'],
            encoding_dim=checkpoint['encoding_dim'],
            noise_factor=checkpoint['noise_factor']
        )
        model.load_state_dict(checkpoint['model_state_dict'])
        model.to(device)
        return model


# ========================
# DCA Implementation
# ========================
class DeterministicDCA:
    """Deterministic Dendritic Cell Algorithm implementation"""
    
    def __init__(self, population_size=100, migration_range=(0.5, 1.5),
                 max_antigens=10, segment_size=1000, anomaly_threshold=0.5):
        self.population_size = population_size
        self.migration_range = migration_range
        self.max_antigens = max_antigens
        self.segment_size = segment_size
        self.anomaly_threshold = anomaly_threshold
        self.antigen_profiles = {}
        
    def process_batch(self, features, signals, antigen_ids=None):
        """Process a batch of data through DCA"""
        if antigen_ids is None:
            antigen_ids = [f"antigen_{i}" for i in range(len(features))]
        
        anomalies = []
        for i, (ag_id, feat, sig) in enumerate(zip(antigen_ids, features, signals)):
            # Simplified DCA logic
            if ag_id not in self.antigen_profiles:
                self.antigen_profiles[ag_id] = {
                    'presentations': 0,
                    'anomaly_presentations': 0
                }
            
            # Determine if anomaly based on signals
            pamp, danger, safe = sig[0], sig[1], sig[2]
            anomaly_score = (pamp + danger - safe) / 3.0
            
            if anomaly_score > 0.5:
                self.antigen_profiles[ag_id]['anomaly_presentations'] += 1
            
            self.antigen_profiles[ag_id]['presentations'] += 1
            
            # Calculate MCAV
            if self.antigen_profiles[ag_id]['presentations'] > 0:
                mcav = (self.antigen_profiles[ag_id]['anomaly_presentations'] / 
                       self.antigen_profiles[ag_id]['presentations'])
                
                if mcav > self.anomaly_threshold:
                    anomalies.append(ag_id)
        
        return anomalies
    
    def save(self, path: str):
        """Save DCA state"""
        state = {
            'population_size': self.population_size,
            'migration_range': self.migration_range,
            'max_antigens': self.max_antigens,
            'segment_size': self.segment_size,
            'anomaly_threshold': self.anomaly_threshold,
            'antigen_profiles': self.antigen_profiles
        }
        joblib.dump(state, path)
    
    @classmethod
    def load(cls, path: str):
        """Load DCA state"""
        state = joblib.load(path)
        dca = cls(
            population_size=state['population_size'],
            migration_range=state['migration_range'],
            max_antigens=state['max_antigens'],
            segment_size=state['segment_size'],
            anomaly_threshold=state['anomaly_threshold']
        )
        dca.antigen_profiles = state['antigen_profiles']
        return dca


# ========================
# Complete Model Class
# ========================
class IntrusionDetectionModel:
    """Complete intrusion detection model using DCA + Denoising Autoencoder"""
    
    def __init__(self, model_dir="saved_models"):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        
        self.autoencoder = None
        self.dca = None
        self.scaler = None
        self.feature_names = None
        self.metrics = {}
        self.threshold = None
        
        # Device configuration
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"Using device: {self.device}")
    
    def define_features(self):
        """Define signal features for intrusion detection"""
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
        
        return signal_features, all_features
    
    def preprocess_data(self, df: pd.DataFrame, fit_scaler: bool = True) -> np.ndarray:
        """Preprocess data with feature engineering"""
        # Define features
        signal_features, all_features = self.define_features()
        
        # Select available features
        available_features = [f for f in all_features if f in df.columns]
        self.feature_names = available_features
        
        # Extract features
        X = df[available_features].copy()
        
        # Handle missing values
        X = X.fillna(0)
        X = X.replace([np.inf, -np.inf], 0)
        
        # Scale features
        if fit_scaler:
            self.scaler = MinMaxScaler()
            X_scaled = self.scaler.fit_transform(X)
        else:
            if self.scaler is None:
                raise ValueError("Scaler not fitted. Call fit() first.")
            X_scaled = self.scaler.transform(X)
        
        return X_scaled
    
    def compute_signals(self, X_scaled: np.ndarray, reconstruction_errors: np.ndarray) -> np.ndarray:
        """Compute PAMP, DANGER, SAFE signals"""
        # Simplified signal computation
        # In practice, you would compute based on actual feature values
        signals = []
        
        for i in range(len(X_scaled)):
            # Use reconstruction error as anomaly indicator
            recon_error = reconstruction_errors[i]
            
            # Generate synthetic signals for demonstration
            pamp = np.random.uniform(0, 1) * (1 + recon_error)
            danger = np.random.uniform(0, 1) * (1 + recon_error * 2)
            safe = np.random.uniform(0, 1) * (1 - recon_error)
            
            signals.append([pamp, danger, safe])
        
        return np.array(signals)
    
    def fit(self, X_train: np.ndarray, epochs: int = 50, learning_rate: float = 1e-3):
        """Train the complete model"""
        print("Training autoencoder...")
        
        # Train autoencoder
        self.autoencoder = DenoisingAutoencoder(
            input_dim=X_train.shape[1],
            encoding_dim=32,
            noise_factor=0.15
        ).to(self.device)
        
        X_train_tensor = torch.FloatTensor(X_train).to(self.device)
        
        # Training setup
        criterion = nn.MSELoss()
        optimizer = torch.optim.Adam(self.autoencoder.parameters(), lr=learning_rate)
        
        # Training loop
        self.autoencoder.train()
        losses = []
        
        for epoch in range(epochs):
            optimizer.zero_grad()
            _, decoded = self.autoencoder(X_train_tensor)
            loss = criterion(decoded, X_train_tensor)
            loss.backward()
            optimizer.step()
            
            losses.append(loss.item())
            
            if (epoch + 1) % 10 == 0:
                print(f"Epoch {epoch + 1}/{epochs}, Loss: {loss.item():.6f}")
        
        print("Autoencoder training complete!")
        
        # Get reconstruction errors
        reconstruction_errors = self.autoencoder.get_reconstruction_error(X_train_tensor)
        
        # Set threshold (95th percentile)
        self.threshold = np.percentile(reconstruction_errors, 95)
        
        # Initialize DCA
        self.dca = DeterministicDCA(
            population_size=100,
            migration_range=(0.5, 1.5),
            max_antigens=10,
            segment_size=1000,
            anomaly_threshold=0.5
        )
        
        # Process training data through DCA
        print("Processing through DCA...")
        signals = self.compute_signals(X_train, reconstruction_errors)
        antigen_ids = [f"train_{i}" for i in range(len(X_train))]
        self.dca.process_batch(X_train, signals, antigen_ids)
        
        # Store metrics
        self.metrics = {
            'final_loss': losses[-1],
            'threshold': float(self.threshold),
            'training_samples': len(X_train),
            'features_count': X_train.shape[1]
        }
        
        return losses
    
    def predict(self, X_test: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions on new data"""
        if self.autoencoder is None:
            raise ValueError("Model not trained. Call fit() first.")
        
        self.autoencoder.eval()
        X_test_tensor = torch.FloatTensor(X_test).to(self.device)
        
        # Get reconstruction errors
        reconstruction_errors = self.autoencoder.get_reconstruction_error(X_test_tensor)
        
        # Autoencoder predictions
        ae_predictions = (reconstruction_errors > self.threshold).astype(int)
        
        # DCA predictions
        signals = self.compute_signals(X_test, reconstruction_errors)
        antigen_ids = [f"test_{i}" for i in range(len(X_test))]
        anomalies = self.dca.process_batch(X_test, signals, antigen_ids)
        
        # Convert DCA anomalies to predictions
        dca_predictions = np.zeros(len(X_test), dtype=int)
        for anomaly in anomalies:
            idx = int(anomaly.split('_')[1])
            if idx < len(dca_predictions):
                dca_predictions[idx] = 1
        
        # Combine predictions (majority voting)
        final_predictions = ((ae_predictions + dca_predictions) >= 1).astype(int)
        
        return final_predictions, reconstruction_errors
    
    def save(self, model_name: str):
        """Save complete model to disk"""
        model_path = os.path.join(self.model_dir, model_name)
        os.makedirs(model_path, exist_ok=True)
        
        # Save autoencoder
        ae_path = os.path.join(model_path, "autoencoder.pth")
        self.autoencoder.save(ae_path)
        
        # Save DCA
        dca_path = os.path.join(model_path, "dca.joblib")
        self.dca.save(dca_path)
        
        # Save scaler and metadata
        metadata = {
            'feature_names': self.feature_names,
            'metrics': self.metrics,
            'threshold': float(self.threshold),
            'scaler': self.scaler,
            'input_shape': self.autoencoder.input_dim
        }
        
        metadata_path = os.path.join(model_path, "metadata.joblib")
        joblib.dump(metadata, metadata_path)
        
        print(f"Model saved to: {model_path}")
        return model_path
    
    @classmethod
    def load(cls, model_path: str):
        """Load complete model from disk"""
        model = cls(model_dir=os.path.dirname(model_path))
        
        # Load metadata
        metadata_path = os.path.join(model_path, "metadata.joblib")
        metadata = joblib.load(metadata_path)
        
        model.feature_names = metadata['feature_names']
        model.metrics = metadata['metrics']
        model.threshold = metadata['threshold']
        model.scaler = metadata['scaler']
        
        # Load autoencoder
        ae_path = os.path.join(model_path, "autoencoder.pth")
        model.autoencoder = DenoisingAutoencoder.load(ae_path, device=model.device)
        
        # Load DCA
        dca_path = os.path.join(model_path, "dca.joblib")
        model.dca = DeterministicDCA.load(dca_path)
        
        return model
    
    def evaluate(self, X_test: np.ndarray, y_true: np.ndarray) -> Dict[str, Any]:
        """Evaluate model performance"""
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        y_pred, reconstruction_errors = self.predict(X_test)
        
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, zero_division=0),
            'recall': recall_score(y_true, y_pred, zero_division=0),
            'f1_score': f1_score(y_true, y_pred, zero_division=0),
            'threshold': float(self.threshold),
            'mean_reconstruction_error': float(np.mean(reconstruction_errors)),
            'anomaly_rate': float(np.mean(y_pred))
        }
        
        return metrics