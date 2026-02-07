# intrusion_detection/model_trainer.py
import os
import joblib
import pandas as pd
import numpy as np
from typing import Tuple, Dict, Any, Optional
from datetime import datetime
import json

from .model import IntrusionDetectionModel

class ModelTrainer:
    """Train and manage intrusion detection models using RNSA+KNN"""
    
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
                   r_s: float = 0.01, max_detectors: int = 1000, 
                   k: int = 1) -> Dict[str, Any]:
        """Train a complete intrusion detection model using RNSA+KNN"""
        print(f"Starting RNSA+KNN model training: {model_name}")
        
        # Load data
        df, y_train = self.load_data(data_path, has_labels=True)
        
        if y_train is None:
            raise ValueError("Training data must have labels")
        
        # Initialize model
        model = IntrusionDetectionModel()
        
        # Preprocess data
        X_train = model.preprocess_data(df, fit_scaler=True)
        
        # Train model
        model.fit(X_train, y_train, r_s=r_s, max_detectors=max_detectors, k=k)
        
        # Evaluate
        metrics = model.evaluate(X_train, y_train)
        print(f"Training metrics: {metrics}")
        
        # Create unique model name with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_name = f"{model_name}_{timestamp}"
        
        # Save model
        model_path = model.save(unique_name)
        
        # Prepare result with all required metrics
        result = {
            'model_path': model_path,
            'model_name': unique_name,
            'metrics': {
                **metrics,
                'test_accuracy': metrics.get('accuracy', 0),
                'detection_rate': metrics.get('detection_rate', 0),
                'false_alarm_rate': metrics.get('false_alarm_rate', 0),
                'auc': metrics.get('roc_auc', 0),
                'detectors': len(model.model.detectors),
                'optimal_dr': metrics.get('detection_rate', 0),
                'optimal_far': metrics.get('false_alarm_rate', 0)
            },
            'training_samples': len(X_train),
            'features_count': X_train.shape[1],
            'parameters': {
                'r_s': r_s,
                'max_detectors': max_detectors,
                'k': k,
                'model_type': 'rnsa_knn'
            }
        }
        
        # Save training log
        log_path = os.path.join(os.path.dirname(model_path), "training_log.json")
        with open(log_path, 'w') as f:
            json.dump(result, f, indent=2)
        
        print(f"✅ Model training completed: {model_path}")
        print(f"   Detectors generated: {len(model.model.detectors)}")
        print(f"   Test accuracy: {metrics.get('accuracy', 0):.4f}")
        print(f"   Detection rate: {metrics.get('detection_rate', 0):.4f}")
        
        return result
    
    def detect_anomalies(self, model_path: str, data_path: str) -> Dict[str, Any]:
        """Detect anomalies in new data using RNSA+KNN"""
        print(f"Loading model from {model_path}")
        
        # Load model
        model = IntrusionDetectionModel.load(model_path)
        
        # Load and preprocess data
        df, _ = self.load_data(data_path, has_labels=False)
        X = model.preprocess_data(df, fit_scaler=False)
        
        # Make predictions
        predictions, confidence_scores = model.predict(X)
        
        # Prepare results
        results = {
            'total_samples': len(predictions),
            'anomalies_detected': int(np.sum(predictions)),
            'anomaly_rate': float(np.mean(predictions)),
            'anomaly_indices': np.where(predictions == 1)[0].tolist(),
            'confidence_scores': confidence_scores.tolist(),
            'threshold': float(model.threshold),
            'mean_confidence': float(np.mean(confidence_scores)),
            'detectors_used': len(model.model.detectors) if hasattr(model.model, 'detectors') else 0
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
        
        # Calculate additional ROC metrics if available
        from sklearn.metrics import roc_curve, auc
        
        if hasattr(model.model, 'predict_proba'):
            proba = model.model.predict_proba(X_test)
            y_scores = proba[:, 1]
            
            # Calculate ROC curve
            fpr, tpr, thresholds = roc_curve(y_true, y_scores)
            roc_auc = auc(fpr, tpr)
            
            # Find optimal threshold (Youden's J statistic)
            youden_j = tpr - fpr
            optimal_idx = np.argmax(youden_j)
            optimal_threshold = thresholds[optimal_idx]
            
            # Calculate metrics at optimal threshold
            y_pred_optimal = (y_scores >= optimal_threshold).astype(int)
            
            from sklearn.metrics import confusion_matrix
            cm = confusion_matrix(y_true, y_pred_optimal)
            TN, FP, FN, TP = cm.ravel()
            
            detection_rate_optimal = TP / (TP + FN) if (TP + FN) > 0 else 0
            false_alarm_rate_optimal = FP / (FP + TN) if (FP + TN) > 0 else 0
            
            # Add ROC metrics
            metrics.update({
                'test_accuracy': metrics.get('accuracy', 0),
                'auc': roc_auc,
                'optimal_threshold': float(optimal_threshold),
                'optimal_dr': float(detection_rate_optimal),
                'optimal_far': float(false_alarm_rate_optimal),
                'fpr': fpr.tolist(),
                'tpr': tpr.tolist()
            })
        
        # Save evaluation results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        eval_path = os.path.join("evaluations", f"evaluation_{timestamp}.json")
        os.makedirs(os.path.dirname(eval_path), exist_ok=True)
        
        with open(eval_path, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        print(f"✅ Model evaluation completed")
        print(f"   Test Accuracy: {metrics.get('accuracy', 0):.4f}")
        print(f"   Detection Rate: {metrics.get('detection_rate', 0):.4f}")
        print(f"   False Alarm Rate: {metrics.get('false_alarm_rate', 0):.4f}")
        print(f"   AUC: {metrics.get('auc', 0):.4f}")
        
        return metrics