# intrusion_detection/model_trainer.py
import os
import joblib
import pandas as pd
import numpy as np
from typing import Tuple, Dict, Any, Optional, List
from datetime import datetime
import json
import warnings
warnings.filterwarnings('ignore')

from .model import IntrusionDetectionModel, find_matching_features, align_features_to_target

class ModelTrainer:
    """Train and manage intrusion detection models using RNSA+KNN with feature alignment"""
    
    def __init__(self, model_dir: str = "saved_models"):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
    
    def load_data(self, data_path: str, has_labels: bool = True) -> Tuple[pd.DataFrame, Optional[np.ndarray]]:
        """Load and validate data"""
        print(f"Loading data from {data_path}")
        
        # Load data
        df = pd.read_csv(data_path)
        
        print(f"Loaded {len(df)} rows with {len(df.columns)} columns")
        
        # Extract labels if present
        y = None
        if has_labels:
            # Look for label column (case-insensitive) - matches CLI detection
            label_cols = ['label', 'Label', ' Label', 'attack_type', 'class', 'Label.1', 'LABEL', 'attack', 'Attack', 'attack_cat']
            for col in label_cols:
                if col in df.columns:
                    # Get original labels first
                    original_labels = df[col].values
                    
                    print(f"Found label column: '{col}'")
                    print(f"  Original labels: {np.unique(original_labels)}")
                    
                    # Convert string labels to binary (0 for normal/benign, 1 for attack/malicious)
                    # MATCHES the logic in cli.py handle_detect method
                    if original_labels.dtype == 'object' or (len(original_labels) > 0 and isinstance(original_labels[0], str)):
                        # Define what counts as normal/benign (case-insensitive) - SAME AS CLI
                        normal_terms = ['benign', 'Benign', 'BENIGN', 'normal', 'Normal', '0', 'false', 'no', 'legitimate']
                        
                        y_binary = []
                        for val in original_labels:
                            val_str = str(val).lower().strip()
                            is_normal = False
                            for term in normal_terms:
                                if term in val_str:
                                    is_normal = True
                                    break
                            
                            if is_normal:
                                y_binary.append(0)  # Normal/Benign
                            else:
                                y_binary.append(1)  # Attack/Malicious
                        
                        y = np.array(y_binary, dtype=np.int32)
                        print(f"  Converted to binary: 0=normal/benign, 1=attack/malicious")
                        print(f"  Class distribution: Normal={np.sum(y==0)}, Attack={np.sum(y==1)}")
                    else:
                        # Already numeric, just convert to int
                        y = original_labels.astype(np.int32)
                        print(f"  Numeric labels: 0={np.sum(y==0)}, 1={np.sum(y==1)}")
                    
                    # Drop label column from features
                    df = df.drop(columns=[col])
                    break
            
            if y is None:
                print("Warning: No label column found. Assuming last column is label.")
                y = df.iloc[:, -1].values
                df = df.iloc[:, :-1]
        
        return df, y
    
    def analyze_dataset_features(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze which of the core features are available in the dataset"""
        from .model import IntrusionDetectionModel
        
        model = IntrusionDetectionModel()
        available_features, feature_mapping = model._find_features_in_data(df)
        
        result = {
            'total_columns': len(df.columns),
            'available_features': available_features,
            'missing_features': [f for f in model.CORE_FEATURES if f not in available_features],
            'feature_mapping': feature_mapping,
            'coverage': len(available_features) / len(model.CORE_FEATURES) * 100
        }
        
        print("\n" + "="*60)
        print("DATASET FEATURE ANALYSIS")
        print("="*60)
        print(f"Core features required: {len(model.CORE_FEATURES)}")
        print(f"Features found: {len(available_features)} ({result['coverage']:.1f}% coverage)")
        
        if result['missing_features']:
            print(f"Missing features: {', '.join(result['missing_features'])}")
            print("(These will be filled with zeros)")
        
        return result
    
    def train_model(self, data_path: str, model_name: str, 
               r_s: float = 0.05, max_detectors: int = 1000, 
               k: int = 5, dataset_name: str = None) -> Dict[str, Any]:
        """Train a complete intrusion detection model using RNSA+KNN with feature alignment"""
        print("\n" + "="*80)
        print(f"RNSA+KNN MODEL TRAINING: {model_name}")
        print("="*80)
        
        # Load data
        df, y_train = self.load_data(data_path, has_labels=True)
        
        if y_train is None:
            raise ValueError("Training data must have labels")
        
        # Analyze dataset features
        feature_analysis = self.analyze_dataset_features(df)
        
        # Initialize model
        model = IntrusionDetectionModel()
        
        # Preprocess data (this will align features automatically)
        X_train = model.preprocess_data(df, fit_scaler=True)
        
        print(f"\nTraining data shape: {X_train.shape}")
        print(f"Class distribution: Normal: {np.sum(y_train == 0)}, Attack: {np.sum(y_train == 1)}")
        
        # Balance classes if needed (optional)
        if np.sum(y_train == 0) > 0 and np.sum(y_train == 1) > 0:
            from sklearn.utils import resample
            
            # Check if classes are imbalanced
            normal_count = np.sum(y_train == 0)
            attack_count = np.sum(y_train == 1)
            
            if normal_count > attack_count * 2:  # If normal > 2x attack
                print("\nBalancing classes...")
                # Downsample normal class
                normal_indices = np.where(y_train == 0)[0]
                attack_indices = np.where(y_train == 1)[0]
                
                sampled_normal_indices = np.random.choice(normal_indices, size=len(attack_indices), replace=False)
                balanced_indices = np.concatenate([sampled_normal_indices, attack_indices])
                np.random.shuffle(balanced_indices)
                
                X_train = X_train[balanced_indices]
                y_train = y_train[balanced_indices]
                
                print(f"Balanced: Normal={np.sum(y_train == 0)}, Attack={np.sum(y_train == 1)}")
        
        # Split data for validation
        from sklearn.model_selection import train_test_split
        X_train_split, X_val, y_train_split, y_val = train_test_split(
            X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
        )
        
        # Train model
        model.fit(
            X_train_split, y_train_split, 
            r_s=r_s, 
            max_detectors=max_detectors, 
            k=k,
            dataset_name=dataset_name or os.path.basename(data_path)
        )
        
        # Evaluate on validation set
        val_metrics = model.evaluate(X_val, y_val)
        
        # Calculate additional metrics
        y_pred_train, _ = model.predict(X_train_split)
        train_accuracy = np.mean(y_pred_train == y_train_split)
        
        # Create unique model name with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_name = f"{model_name}_{timestamp}"
        
        # Save model
        model_path = model.save(unique_name)
        
        # Prepare result with all metrics
        result = {
            'model_path': model_path,
            'model_name': unique_name,
            'training_samples': len(X_train_split),  # ADD THIS - actual training samples used
            'validation_samples': len(X_val),
            'features_count': X_train.shape[1],
            'metrics': {
                'train_accuracy': float(train_accuracy),
                'test_accuracy': float(val_metrics.get('accuracy', 0)),
                'detection_rate': float(val_metrics.get('detection_rate', 0)),
                'false_alarm_rate': float(val_metrics.get('false_alarm_rate', 0)),
                'auc': float(val_metrics.get('roc_auc', 0)),
                'precision': float(val_metrics.get('precision', 0)),
                'recall': float(val_metrics.get('recall', 0)),
                'f1_score': float(val_metrics.get('f1_score', 0)),
                'detectors': len(model.model.detectors) if model.model else 0,
                'optimal_dr': float(val_metrics.get('detection_rate', 0)),
                'optimal_far': float(val_metrics.get('false_alarm_rate', 0)),
                'training_samples': len(X_train_split),  # ADD THIS to metrics too
                'features_count': X_train.shape[1]  # ADD THIS to metrics too
            },
            'feature_analysis': feature_analysis,
            'parameters': {
                'r_s': r_s,
                'max_detectors': max_detectors,
                'k': k,
                'model_type': 'rnsa_knn',
                'training_samples': len(X_train_split)  # ADD THIS
            },
            'dataset_name': dataset_name or os.path.basename(data_path),
            'timestamp': timestamp
        }
        
        # Save training log
        log_path = os.path.join(os.path.dirname(model_path), f"training_log_{timestamp}.json")
        with open(log_path, 'w') as f:
            json.dump(result, f, indent=2)
        
        print("\n" + "="*60)
        print("TRAINING COMPLETE")
        print("="*60)
        print(f"Model saved: {model_path}")
        print(f"Training samples: {len(X_train_split):,}")
        print(f"Detectors generated: {result['metrics']['detectors']}")
        print(f"Train accuracy: {result['metrics']['train_accuracy']:.4f}")
        print(f"Test accuracy: {result['metrics']['test_accuracy']:.4f}")
        print(f"Detection rate: {result['metrics']['detection_rate']:.4f}")
        print(f"False alarm rate: {result['metrics']['false_alarm_rate']:.4f}")
        print(f"AUC: {result['metrics']['auc']:.4f}")
        
        return result

    def detect_anomalies(self, model_path: str, data_path: str, 
                        threshold: float = None) -> Dict[str, Any]:
        """Detect anomalies in new data - exactly like RNSA_KNN_training code"""
        print("\n" + "="*80)
        print("ANOMALY DETECTION ON UNSEEN DATA")
        print("="*80)
        
        print(f"Loading model from: {model_path}")
        
        # Load model
        model = IntrusionDetectionModel.load(model_path)
        
        # Load data - like training code
        print(f"Loading data from: {data_path}")
        df = pd.read_csv(data_path)
        print(f"Data loaded: {len(df)} samples, {len(df.columns)} features")
        
        # Use provided threshold or default
        if threshold is not None:
            original_threshold = model.threshold
            model.threshold = threshold
            print(f"Using custom threshold: {threshold:.4f}")
        else:
            print(f"Using default threshold: {model.threshold:.4f}")
        
        # Preprocess data to align features (like training code)
        print("\n" + "="*60)
        print("PREPROCESSING DATA TO ALIGN FEATURES")
        print("="*60)
        
        # Clean data
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        
        # Use model's preprocessing (this handles feature alignment)
        X = model.preprocess_data(df, fit_scaler=False)
        
        print(f"\nAligned data shape: {X.shape}")
        print(f"Features used: {model.feature_names}")
        
        # Make predictions (like training code)
        print("\n" + "="*60)
        print("RUNNING ANOMALY DETECTION")
        print("="*60)
        
        predictions, confidence_scores = model.predict(X)
        
        # Apply threshold
        thresholded_predictions = (confidence_scores >= model.threshold).astype(int)
        
        # Get anomaly indices
        anomaly_indices = np.where(thresholded_predictions == 1)[0]
        
        # Print anomaly summary (like training code)
        print(f"\n{'='*60}")
        print("ANOMALY DETECTION SUMMARY")
        print(f"{'='*60}")
        print(f"Total samples analyzed: {len(predictions)}")
        print(f"Anomalies detected: {len(anomaly_indices)}")
        print(f"Anomaly rate: {len(anomaly_indices)/len(predictions):.2%}")
        print(f"Mean confidence score: {np.mean(confidence_scores):.4f}")
        print(f"Std confidence score: {np.std(confidence_scores):.4f}")
        print(f"Detection threshold: {model.threshold:.4f}")
        print(f"Detectors used: {len(model.model.detectors) if hasattr(model.model, 'detectors') else 0}")
        
        # Print detailed anomaly list (like training code)
        print(f"\n{'='*80}")
        print("DETECTED ANOMALIES (First 50)")
        print(f"{'='*80}")
        print(f"{'Index':<10} {'Confidence':<15} {'Severity':<10} {'Top Features'}")
        print(f"{'-'*80}")
        
        # Get the original aligned data for feature values
        X_aligned_df = None
        if hasattr(model, 'feature_names') and model.feature_names:
            # Create a DataFrame with the aligned features
            X_aligned_df = pd.DataFrame(X, columns=model.feature_names)
        
        for idx in anomaly_indices[:50]:
            confidence = confidence_scores[idx]
            severity = self._calculate_severity(confidence)
            
            # Get top feature values (like training code)
            feature_str = ""
            if X_aligned_df is not None and idx < len(X_aligned_df):
                row = X_aligned_df.iloc[idx]
                top_features = []
                # Nice display names
                nice_names = {
                    'dur': 'Duration', 'spkts': 'Src Pkts', 'dpkts': 'Dst Pkts',
                    'sbytes': 'Src Bytes', 'dbytes': 'Dst Bytes', 'rate': 'Flow Rate',
                    'smean': 'Src Pkt Mean', 'dmean': 'Dst Pkt Mean',
                    'swin': 'Src Window', 'dwin': 'Dst Window'
                }
                for i, feat in enumerate(model.feature_names[:5]):
                    if i < len(row):
                        val = row.iloc[i] if hasattr(row, 'iloc') else row[i]
                        display_name = nice_names.get(feat, feat)
                        if isinstance(val, (int, float)):
                            top_features.append(f"{display_name}={val:.2f}")
                        else:
                            top_features.append(f"{display_name}={val}")
                feature_str = ", ".join(top_features)
            
            print(f"{idx:<10} {confidence:<15.6f} {severity:<10} {feature_str}")
        
        if len(anomaly_indices) > 50:
            print(f"\n... and {len(anomaly_indices) - 50} more anomalies")
        
        # Create detailed anomaly list for JSON
        anomalies = []
        for idx in anomaly_indices[:100]:
            anomaly = {
                'index': int(idx),
                'confidence': float(confidence_scores[idx]),
                'severity': self._calculate_severity(confidence_scores[idx])
            }
            
            # Add feature values if available
            if X_aligned_df is not None and idx < len(X_aligned_df):
                row = X_aligned_df.iloc[idx]
                top_features = {}
                for i, feat in enumerate(model.feature_names[:10]):
                    if i < len(row):
                        val = row.iloc[i] if hasattr(row, 'iloc') else row[i]
                        top_features[feat] = float(val) if isinstance(val, (int, float)) else str(val)
                anomaly['top_features'] = top_features
            
            anomalies.append(anomaly)
        
        results = {
            'total_samples': int(len(predictions)),
            'anomalies_detected': int(np.sum(thresholded_predictions)),
            'anomaly_rate': float(np.mean(thresholded_predictions)),
            'anomaly_indices': anomaly_indices.tolist()[:1000],
            'anomalies': anomalies,
            'mean_confidence': float(np.mean(confidence_scores)),
            'std_confidence': float(np.std(confidence_scores)),
            'threshold': float(model.threshold),
            'detectors_used': len(model.model.detectors) if hasattr(model.model, 'detectors') else 0,
            'features_used': model.feature_names,
            'feature_mapping': model.feature_mapping
        }
        
        # Save detection results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        detections_dir = os.path.join("detections")
        os.makedirs(detections_dir, exist_ok=True)
        results_path = os.path.join(detections_dir, f"detection_{timestamp}.json")
        
        # Convert numpy types to Python types for JSON serialization
        def convert_to_serializable(obj):
            if isinstance(obj, np.integer):
                return int(obj)
            elif isinstance(obj, np.floating):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, dict):
                return {k: convert_to_serializable(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_to_serializable(v) for v in obj]
            else:
                return obj
        
        serializable_results = convert_to_serializable(results)
        
        with open(results_path, 'w') as f:
            json.dump(serializable_results, f, indent=2)
        
        print(f"\n{'='*60}")
        print("DETECTION COMPLETE")
        print(f"{'='*60}")
        print(f"Results saved to: {results_path}")
        
        # Restore original threshold if changed
        if threshold is not None:
            model.threshold = original_threshold
        
        return results
    
    def _calculate_severity(self, confidence: float) -> str:
        """Calculate severity based on confidence score"""
        if confidence >= 0.95:
            return "Critical"
        elif confidence >= 0.85:
            return "High"
        elif confidence >= 0.70:
            return "Medium"
        elif confidence >= 0.50:
            return "Low"
        else:
            return "Minimal"
    
    def evaluate_model(self, model_path: str, test_data_path: str) -> Dict[str, Any]:
        """Evaluate model on test data with feature alignment"""
        print("\n" + "="*80)
        print("MODEL EVALUATION")
        print("="*80)
        
        print(f"Loading model from {model_path}")
        
        # Load model
        model = IntrusionDetectionModel.load(model_path)
        
        # Load test data
        df, y_true = self.load_data(test_data_path, has_labels=True)
        
        if y_true is None:
            raise ValueError("Test data must have labels for evaluation")
        
        # Analyze dataset features
        feature_analysis = self.analyze_dataset_features(df)
        
        # Preprocess data
        X_test = model.preprocess_data(df, fit_scaler=False)
        
        # Evaluate
        metrics = model.evaluate(X_test, y_true)
        
        # Calculate additional ROC metrics
        from sklearn.metrics import roc_curve, auc, confusion_matrix
        
        predictions, confidence_scores = model.predict(X_test)
        
        # Calculate ROC curve
        fpr, tpr, thresholds = roc_curve(y_true, confidence_scores)
        roc_auc = auc(fpr, tpr)
        
        # Find optimal threshold
        threshold = tpr - fpr
        optimal_idx = np.argmax(threshold)
        optimal_threshold = thresholds[optimal_idx]
        
        # Calculate metrics at optimal threshold
        y_pred_optimal = (confidence_scores >= optimal_threshold).astype(int)
        cm = confusion_matrix(y_true, y_pred_optimal)
        if cm.shape == (2, 2):
            TN, FP, FN, TP = cm.ravel()
            optimal_dr = TP / (TP + FN) if (TP + FN) > 0 else 0
            optimal_far = FP / (FP + TN) if (FP + TN) > 0 else 0
        else:
            optimal_dr = 0
            optimal_far = 0
        
        # Add ROC metrics
        metrics.update({
            'test_accuracy': metrics.get('accuracy', 0),
            'auc': float(roc_auc),
            'optimal_threshold': float(optimal_threshold),
            'optimal_dr': float(optimal_dr),
            'optimal_far': float(optimal_far),
            'fpr': fpr.tolist(),
            'tpr': tpr.tolist(),
            'thresholds': thresholds.tolist(),
            'feature_analysis': feature_analysis,
            'model_features': model.feature_names,
            'feature_mapping': model.feature_mapping
        })
        
        # Save evaluation results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        eval_path = os.path.join("evaluations", f"evaluation_{timestamp}.json")
        os.makedirs(os.path.dirname(eval_path), exist_ok=True)
        
        # Convert numpy types to Python types
        def convert_to_serializable(obj):
            if isinstance(obj, np.integer):
                return int(obj)
            elif isinstance(obj, np.floating):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, dict):
                return {k: convert_to_serializable(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_to_serializable(v) for v in obj]
            else:
                return obj
        
        serializable_metrics = convert_to_serializable(metrics)
        
        with open(eval_path, 'w') as f:
            json.dump(serializable_metrics, f, indent=2)
        
        print("\n" + "="*60)
        print("EVALUATION COMPLETE")
        print("="*60)
        print(f"Test samples: {len(X_test)}")
        print(f"Test Accuracy: {metrics.get('accuracy', 0):.4f}")
        print(f"Detection Rate: {metrics.get('detection_rate', 0):.4f}")
        print(f"False Alarm Rate: {metrics.get('false_alarm_rate', 0):.4f}")
        print(f"AUC: {metrics.get('auc', 0):.4f}")
        print(f"Results saved: {eval_path}")
        
        return metrics