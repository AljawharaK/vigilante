# intrusion_detection/model_trainer.py
import os
import joblib
import torch
import pandas as pd
import numpy as np
from typing import Tuple, Dict, Any, Optional
from datetime import datetime
import json

from .model import IntrusionDetectionModel

class ModelTrainer:
    """Train and manage intrusion detection models"""
    
    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
    
    def load_data(self, data_path: str, has_labels: bool = True) -> Tuple[pd.DataFrame, Optional[np.ndarray]]:
        """Load and validate data"""
        print(f"Loading data from {data_path}")
        
        # Load data
        df = pd.read_csv(data_path)
        
        # Check for required columns
        required_cols = ['rate', 'sload', 'dload', 'spkts', 'dpkts', 
                        'sbytes', 'dbytes', 'dur', 'sinpkt', 'dinpkt']
        
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            print(f"Warning: Missing columns: {missing_cols}")
            print("Using available columns only")
        
        # Extract labels if present
        if has_labels and 'label' in df.columns:
            y = df['label'].values
        else:
            y = None
        
        return df, y
    
    def train_model(self, data_path: str, model_name: str, 
                   epochs: int = 50, learning_rate: float = 1e-3) -> Dict[str, Any]:
        """Train a complete intrusion detection model"""
        print(f"Starting model training: {model_name}")
        
        # Load data
        df, y_train = self.load_data(data_path, has_labels=True)
        
        # Initialize model
        model = IntrusionDetectionModel()
        
        # Preprocess data
        X_train = model.preprocess_data(df, fit_scaler=True)
        
        # Train model
        losses = model.fit(X_train, epochs=epochs, learning_rate=learning_rate)
        
        # Evaluate if labels are available
        if y_train is not None:
            metrics = model.evaluate(X_train, y_train)
            print(f"Training metrics: {metrics}")
        else:
            metrics = model.metrics
        
        # Create unique model name with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_name = f"{model_name}_{timestamp}"
        
        # Save model
        model_path = model.save(unique_name)
        
        # Prepare result
        result = {
            'model_path': model_path,
            'model_name': unique_name,
            'metrics': metrics,
            'training_samples': len(X_train),
            'features_count': X_train.shape[1],
            'loss_history': [float(l) for l in losses] if losses else []
        }
        
        # Save training log
        log_path = os.path.join(os.path.dirname(model_path), "training_log.json")
        with open(log_path, 'w') as f:
            json.dump(result, f, indent=2)
        
        print(f"✅ Model training completed: {model_path}")
        return result
    
    def detect_anomalies(self, model_path: str, data_path: str) -> Dict[str, Any]:
        """Detect anomalies in new data"""
        print(f"Loading model from {model_path}")
        
        # Load model
        model = IntrusionDetectionModel.load(model_path)
        
        # Load and preprocess data
        df, _ = self.load_data(data_path, has_labels=False)
        X = model.preprocess_data(df, fit_scaler=False)
        
        # Make predictions
        predictions, reconstruction_errors = model.predict(X)
        
        # Prepare results
        results = {
            'total_samples': len(predictions),
            'anomalies_detected': int(np.sum(predictions)),
            'anomaly_rate': float(np.mean(predictions)),
            'anomaly_indices': np.where(predictions == 1)[0].tolist(),
            'reconstruction_errors': reconstruction_errors.tolist(),
            'threshold': float(model.threshold),
            'mean_reconstruction_error': float(np.mean(reconstruction_errors))
        }
        
        # Save detection results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_path = os.path.join("detections", f"detection_{timestamp}.json")
        os.makedirs(os.path.dirname(results_path), exist_ok=True)
        
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"✅ Anomaly detection completed")
        print(f"   Anomalies detected: {results['anomalies_detected']}/{results['total_samples']}")
        print(f"   Anomaly rate: {results['anomaly_rate']:.2%}")
        
        return results
    
    def evaluate_model(self, model_path: str, test_data_path: str) -> Dict[str, Any]:
        """Evaluate model on test data"""
        print(f"Evaluating model: {model_path}")
        
        # Load model
        model = IntrusionDetectionModel.load(model_path)
        
        # Load test data
        df, y_true = self.load_data(test_data_path, has_labels=True)
        
        # Preprocess data
        X_test = model.preprocess_data(df, fit_scaler=False)
        
        # Evaluate
        metrics = model.evaluate(X_test, y_true)
        
        # Save evaluation results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        eval_path = os.path.join("evaluations", f"evaluation_{timestamp}.json")
        os.makedirs(os.path.dirname(eval_path), exist_ok=True)
        
        with open(eval_path, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        print(f"✅ Model evaluation completed")
        print(f"   Accuracy: {metrics['accuracy']:.4f}")
        print(f"   Precision: {metrics['precision']:.4f}")
        print(f"   Recall: {metrics['recall']:.4f}")
        print(f"   F1-Score: {metrics['f1_score']:.4f}")
        
        return metrics