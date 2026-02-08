# intrusion_detection/model.py
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.neighbors import KNeighborsClassifier
from typing import Tuple, Dict, Any, Optional, List

# ========================
# Proposed Algorithm RNSA + KNN
# ========================
class Detector:
    """Represents a mature detector with center and radius"""
    def __init__(self, center: np.ndarray, radius: float):
        self.center = center
        self.radius = radius

    def covers(self, sample: np.ndarray) -> bool:
        """Check if detector covers a sample"""
        distance = np.linalg.norm(sample - self.center)
        return distance <= self.radius

    def coverage_score(self, sample: np.ndarray) -> float:
        """Calculate how well a sample is covered by this detector (0 to 1)"""
        distance = np.linalg.norm(sample - self.center)
        if distance <= self.radius:
            # If inside detector, score = 1 - (distance/radius)
            return 1.0 - (distance / self.radius)
        else:
            return 0.0

class RNSA_KNN_Model:
    """
    Implementation of the RNSA+KNN algorithm from the 2019 paper
    Uses abnormal samples as detector centers + KNN for hole samples
    """

    def __init__(self, r_s: float = 0.01, max_detectors: int = 1000,
                 k: int = 1, estimated_coverage: float = 0.99):
        """
        Parameters:
        -----------
        r_s : float
            Self radius for tolerance checking
        max_detectors : int
            Maximum number of detectors to generate
        k : int
            Number of neighbors for KNN reclassification (for holes)
        estimated_coverage : float
            Estimated coverage threshold (from paper)
        Others:
        -----------
        D   : S
            Detector set initialized to an empty set
        r   : float
            Minimum distance to self - r_s
        Euclidean: metric
            Calculates distance between the detector and the sample
        """
        self.r_s = r_s
        self.max_detectors = max_detectors
        self.k = k
        self.estimated_coverage = estimated_coverage
        self.detectors: List[Detector] = []
        self.knn = KNeighborsClassifier(n_neighbors=k)
        self.scaler = MinMaxScaler()
        self.feature_names = None
        self.metrics = {}
        self.threshold = 0.5

    def _euclidean_distance(self, a: np.ndarray, b: np.ndarray) -> float:
        """Calculate Euclidean distance between two vectors"""
        return np.linalg.norm(a - b)

    def _calculate_radius(self, candidate_center: np.ndarray,
                          normal_samples: np.ndarray) -> Tuple[bool, float]:
        """
        Calculate detector radius based on minimum distance to normal samples
        Returns: (is_valid, radius)
        """
        min_distance = float('inf')

        for normal_sample in normal_samples:
            distance = self._euclidean_distance(candidate_center, normal_sample)
            if distance < min_distance:
                min_distance = distance

        # Radius = distance to closest normal sample - self_radius
        radius = min_distance - self.r_s

        # Detector is valid if radius > 0 (not overlapping with self-region)
        is_valid = radius > 0

        return is_valid, radius

    def _is_redundant(self, candidate_center: np.ndarray) -> bool:
        """
        Check if candidate detector is redundant (covered by existing detectors)
        """
        for detector in self.detectors:
            if detector.covers(candidate_center):
                return True
        return False

    def fit(self, X_train: np.ndarray, y_train: np.ndarray):
        """
        Train the model using both normal and abnormal samples

        Parameters:
        -----------
        X_train : np.ndarray
            Training features
        y_train : np.ndarray
            Training labels (0=normal, 1=abnormal)
        """
        # Normalize data
        X_train_scaled = self.scaler.fit_transform(X_train)

        # Separate normal and abnormal samples
        normal_mask = (y_train == 0)
        abnormal_mask = (y_train == 1)

        normal_samples = X_train_scaled[normal_mask]
        abnormal_samples = X_train_scaled[abnormal_mask]

        print(f"Training with {len(normal_samples)} normal and {len(abnormal_samples)} abnormal samples")

        # PHASE 1: Generate detectors from abnormal samples (Algorithm 1 from paper)
        print("Phase 1: Generating detectors from abnormal samples...")
        self.detectors = []

        for i, abnormal_sample in enumerate(abnormal_samples):
            if len(self.detectors) >= self.max_detectors:
                break

            # Check redundancy with existing detectors (lines 3-6 in pseudocode)
            if self._is_redundant(abnormal_sample):
                continue

            # Tolerance check and radius calculation (lines 7-10 in pseudocode)
            is_valid, radius = self._calculate_radius(abnormal_sample, normal_samples)

            if is_valid:
                # Create new detector with calculated radius
                detector = Detector(abnormal_sample.copy(), radius)
                self.detectors.append(detector)

            if (i + 1) % 100 == 0:
                print(f"  Processed {i+1}/{len(abnormal_samples)} abnormal samples, "
                      f"generated {len(self.detectors)} detectors")

        print(f"Generated {len(self.detectors)} mature detectors")

        # PHASE 2: Train KNN for hole remediation
        print("Phase 2: Training KNN for hole remediation...")
        self.knn.fit(X_train_scaled, y_train)

        return self

    def _nsa_classify(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        NSA classification phase
        Returns: (predictions, hole_samples_mask, covered_samples_mask)
        """
        X_scaled = self.scaler.transform(X)
        n_samples = len(X_scaled)

        predictions = np.zeros(n_samples, dtype=int)  # Default: normal (0)
        covered_mask = np.zeros(n_samples, dtype=bool)  # Samples covered by detectors

        # Check each sample against all detectors
        for i, sample in enumerate(X_scaled):
            for detector in self.detectors:
                if detector.covers(sample):
                    predictions[i] = 1  # Abnormal
                    covered_mask[i] = True
                    break

        # Samples in holes are those NOT covered by any detector
        hole_mask = ~covered_mask

        return predictions, hole_mask, covered_mask

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict using two-phase approach: NSA + KNN reclassification

        Parameters:
        -----------
        X : np.ndarray
            Test features

        Returns:
        --------
        predictions : np.ndarray
            Predicted labels (0=normal, 1=abnormal)
        """
        # Phase 1: NSA classification
        nsa_predictions, hole_mask, _ = self._nsa_classify(X)

        # Phase 2: KNN reclassification only for samples in holes
        if np.any(hole_mask):
            X_scaled = self.scaler.transform(X)
            hole_samples = X_scaled[hole_mask]

            # Reclassify hole samples using KNN
            knn_predictions = self.knn.predict(hole_samples)

            # Update predictions for hole samples
            final_predictions = nsa_predictions.copy()
            final_predictions[hole_mask] = knn_predictions
        else:
            final_predictions = nsa_predictions

        return final_predictions

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Predict probability scores for ROC curve
        For NSA+KNN: Use maximum detector coverage score for NSA part,
        then blend with KNN probabilities for hole samples
        """
        X_scaled = self.scaler.transform(X)
        n_samples = len(X_scaled)

        # Initialize probability scores
        prob_scores = np.zeros(n_samples, dtype=float)

        # Phase 1: NSA coverage scores
        for i, sample in enumerate(X_scaled):
            max_coverage = 0.0
            for detector in self.detectors:
                coverage = detector.coverage_score(sample)
                if coverage > max_coverage:
                    max_coverage = coverage
            prob_scores[i] = max_coverage

        # Phase 2: Get KNN probabilities for all samples
        # This gives us probabilities for both covered and hole samples
        knn_proba = self.knn.predict_proba(X_scaled)

        # For the proposed algorithm:
        # Samples covered by detectors use NSA score (higher weight)
        # Samples in holes use KNN score (higher weight)
        nsa_predictions, hole_mask, _ = self._nsa_classify(X)

        # Blend probabilities
        # For covered samples: 70% NSA, 30% KNN
        # For hole samples: 30% NSA, 70% KNN
        for i in range(n_samples):
            if not hole_mask[i]:  # Covered by detector
                prob_scores[i] = 0.7 * prob_scores[i] + 0.3 * knn_proba[i, 1]
            else:  # In hole
                prob_scores[i] = 0.3 * prob_scores[i] + 0.7 * knn_proba[i, 1]

        # Convert to 2D array expected by sklearn
        proba_array = np.zeros((n_samples, 2))
        proba_array[:, 0] = 1 - prob_scores  # Probability of class 0 (normal)
        proba_array[:, 1] = prob_scores      # Probability of class 1 (abnormal)

        return proba_array
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """Evaluate model and return comprehensive metrics"""
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        from sklearn.metrics import confusion_matrix, roc_curve, auc
        
        # Make predictions
        y_pred = self.predict(X_test)
        y_scores = self.predict_proba(X_test)[:, 1]
        
        # Calculate basic metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        
        # Calculate confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        if cm.shape == (2, 2):
            TN, FP, FN, TP = cm.ravel()
            detection_rate = TP / (TP + FN) if (TP + FN) > 0 else 0
            false_alarm_rate = FP / (FP + TN) if (FP + TN) > 0 else 0
        else:
            TN, FP, FN, TP = 0, 0, 0, 0
            detection_rate = 0
            false_alarm_rate = 0
        
        # Calculate ROC metrics
        fpr, tpr, thresholds = roc_curve(y_test, y_scores)
        roc_auc = auc(fpr, tpr)
        
        # Find optimal threshold (Youden's J statistic)
        youden_j = tpr - fpr
        optimal_idx = np.argmax(youden_j)
        optimal_threshold = thresholds[optimal_idx]
        
        # Calculate metrics at optimal threshold
        y_pred_optimal = (y_scores >= optimal_threshold).astype(int)
        cm_optimal = confusion_matrix(y_test, y_pred_optimal)
        if cm_optimal.shape == (2, 2):
            TN_opt, FP_opt, FN_opt, TP_opt = cm_optimal.ravel()
            optimal_dr = TP_opt / (TP_opt + FN_opt) if (TP_opt + FN_opt) > 0 else 0
            optimal_far = FP_opt / (FP_opt + TN_opt) if (FP_opt + TN_opt) > 0 else 0
        else:
            optimal_dr = 0
            optimal_far = 0
        
        # Get number of anomalies detected
        anomalies_detected = int(np.sum(y_pred))
        
        return {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'detection_rate': float(detection_rate),
            'false_alarm_rate': float(false_alarm_rate),
            'auc': float(roc_auc),
            'optimal_threshold': float(optimal_threshold),
            'optimal_dr': float(optimal_dr),
            'optimal_far': float(optimal_far),
            'true_positives': int(TP),
            'false_positives': int(FP),
            'true_negatives': int(TN),
            'false_negatives': int(FN),
            'anomalies_detected': anomalies_detected,
            'anomaly_rate': float(anomalies_detected / len(y_test)) if len(y_test) > 0 else 0,
            'threshold': float(self.threshold),
            'detectors_count': len(self.detectors)
        }

    def save(self, path: str):
        """Save model to file"""
        model_data = {
            'r_s': self.r_s,
            'max_detectors': self.max_detectors,
            'k': self.k,
            'estimated_coverage': self.estimated_coverage,
            'detectors': [(det.center.tolist(), det.radius) for det in self.detectors],
            'scaler': self.scaler,
            'knn': self.knn,
            'feature_names': self.feature_names,
            'metrics': self.metrics,
            'threshold': self.threshold,
        }
        joblib.dump(model_data, path)
        print(f"Model saved to: {path}")
        return path

    @classmethod
    def load(cls, path: str):
        """Load model from file"""
        model_data = joblib.load(path)
        model = cls(
            r_s=model_data['r_s'],
            max_detectors=model_data['max_detectors'],
            k=model_data['k'],
            estimated_coverage=model_data['estimated_coverage']
        )
        
        model.detectors = [
            Detector(np.array(center), radius) 
            for center, radius in model_data['detectors']
        ]
        
        model.scaler = model_data['scaler']
        model.knn = model_data['knn']
        model.feature_names = model_data['feature_names']
        model.metrics = model_data['metrics']
        model.threshold = model_data['threshold']
        
        return model

# ========================
# Complete Model Class
# ========================
class IntrusionDetectionModel:
    """Complete intrusion detection model using RNSA + KNN"""
    
    def __init__(self, model_dir="saved_models"):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.metrics = {}
        self.threshold = 0.5
    
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
        """Robust preprocessing that handles different dataset formats"""
        try:
            # Define common features across different IDS datasets
            common_features = self._get_common_features(df)
        
            if not common_features:
                raise ValueError("No compatible features found between model and input data")
        
            self.feature_names = common_features
            print(f"Using {len(common_features)} features for detection")
        
            # Extract and clean features
            X = df[common_features].copy()
        
            # Handle missing values
            X = X.fillna(0)
            X = X.replace([np.inf, -np.inf], 0)
        
            # Ensure numeric types
            X = X.apply(pd.to_numeric, errors='coerce').fillna(0)
        
            # Scale features
            if fit_scaler:
                self.scaler = MinMaxScaler()
                X_scaled = self.scaler.fit_transform(X)
            else:
                if self.scaler is None:
                    raise ValueError("Scaler not fitted. Call fit() first.")
                X_scaled = self.scaler.transform(X)
        
            return X_scaled
        
        except Exception as e:
            print(f"Preprocessing error: {e}")
            raise

    def _get_common_features(self, df: pd.DataFrame) -> list:
        """Get common features between model and input data"""
        # If model has defined feature names, use those
        if hasattr(self, 'feature_names') and self.feature_names:
            model_features = self.feature_names
        elif hasattr(self, 'model') and hasattr(self.model, 'feature_names') and self.model.feature_names:
            model_features = self.model.feature_names
        else:
            # Fallback to standard features
            model_features = self.define_features()[1]  # Get all_features from define_features()
    
        # Get available features in input data
        available_features = list(df.columns)
    
        # Find intersection
        common_features = [f for f in model_features if f in available_features]
    
        # If no common features, try to map similar features
        if not common_features:
            common_features = self._map_similar_features(model_features, available_features)
    
        return common_features

    def _map_similar_features(self, model_features: list, available_features: list) -> list:
        """Map similar feature names between different datasets"""
        feature_mappings = {
            # UNSW-NB15 to CIC mappings
            'sbytes': ['TotLen Fwd Pkts', 'Fwd Pkt Len Max', 'Flow Byts/s'],
            'dbytes': ['TotLen Bwd Pkts', 'Bwd Pkt Len Max'],
            'spkts': ['Tot Fwd Pkts', 'Fwd Pkts/s'],
            'dpkts': ['Tot Bwd Pkts', 'Bwd Pkts/s'],
            'dur': ['Flow Duration', 'Flow IAT Mean'],
            'sload': ['Fwd Pkt Len Mean', 'Flow Byts/s'],
            'dload': ['Bwd Pkt Len Mean', 'Flow Byts/s'],
            'sinpkt': ['Fwd IAT Mean', 'Flow IAT Mean'],
            'dinpkt': ['Bwd IAT Mean', 'Flow IAT Mean'],
            'rate': ['Flow Pkts/s', 'Flow Byts/s'],
        
            # Common network features
            'protocol': ['Protocol', 'proto'],
            'src_port': ['Src Port', 'sport'],
            'dst_port': ['Dst Port', 'dport'],
            'src_ip': ['Src IP', 'srcip'],
            'dst_ip': ['Dst IP', 'dstip']
        }
    
        common_features = []
        for model_feature in model_features:
            if model_feature in available_features:
                common_features.append(model_feature)
            elif model_feature in feature_mappings:
                for mapped_feature in feature_mappings[model_feature]:
                    if mapped_feature in available_features:
                        common_features.append(mapped_feature)
                        break
    
        return common_features
    
    def fit(self, X_train: np.ndarray, y_train: np.ndarray, 
           r_s: float = 0.01, max_detectors: int = 1000, k: int = 1):
        """Train the RNSA+KNN model"""
        print("Training RNSA+KNN model...")
        
        # Initialize and train model
        self.model = RNSA_KNN_Model(
            r_s=r_s,
            max_detectors=max_detectors,
            k=k
        )
        
        self.model.fit(X_train, y_train)
        
        # Set threshold (you can adjust this based on validation)
        self.threshold = 0.5
        
        # Store metrics
        self.metrics = {
            'training_samples': len(X_train),
            'features_count': X_train.shape[1],
            'detectors_count': len(self.model.detectors),
            'r_s': r_s,
            'max_detectors': max_detectors,
            'k': k
        }
        
        print("RNSA+KNN training complete!")
        return self
    
    def predict(self, X_test: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions on new data"""
        if self.model is None:
            raise ValueError("Model not trained. Call fit() first.")
        
        # Get predictions
        predictions = self.model.predict(X_test)
        
        # Get probability scores for reconstruction errors (using coverage scores)
        proba = self.model.predict_proba(X_test)
        confidence_scores = proba[:, 1]  # Probability of being abnormal
        
        return predictions, confidence_scores
    
    def evaluate(self, X_test: np.ndarray, y_true: np.ndarray) -> Dict[str, Any]:
        """Evaluate model performance"""
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        from sklearn.metrics import roc_auc_score, confusion_matrix
    
        y_pred, confidence_scores = self.predict(X_test)
    
        # Calculate basic metrics
        metrics = {
            'accuracy': float(accuracy_score(y_true, y_pred)),
            'precision': float(precision_score(y_true, y_pred, zero_division=0)),
            'recall': float(recall_score(y_true, y_pred, zero_division=0)),
            'f1_score': float(f1_score(y_true, y_pred, zero_division=0)),
            'threshold': float(self.threshold)
        }
        
        # Calculate ROC AUC if we have probability scores
        if confidence_scores is not None:
            try:
                metrics['roc_auc'] = float(roc_auc_score(y_true, confidence_scores))
            except:
                metrics['roc_auc'] = 0.0
        
        # Calculate confusion matrix metrics
        try:
            cm = confusion_matrix(y_true, y_pred)
            TN, FP, FN, TP = cm.ravel()
            
            metrics['true_positive'] = int(TP)
            metrics['false_positive'] = int(FP)
            metrics['true_negative'] = int(TN)
            metrics['false_negative'] = int(FN)
            
            # Detection Rate (Recall)
            metrics['detection_rate'] = float(TP / (TP + FN)) if (TP + FN) > 0 else 0.0
            
            # False Alarm Rate (False Positive Rate)
            metrics['false_alarm_rate'] = float(FP / (FP + TN)) if (FP + TN) > 0 else 0.0
            
        except:
            pass
    
        return metrics
    
    def save(self, model_name: str):
        """Save complete model to disk - as single file"""
        # Ensure .joblib extension
        if not model_name.endswith('.joblib'):
            model_name = f"{model_name}.joblib"
        
        model_path = os.path.join(self.model_dir, model_name)
        
        # Save all model data in one file
        model_data = {
            'model': self.model,
            'feature_names': self.feature_names,
            'metrics': self.metrics,
            'threshold': float(self.threshold),
            'model_type': 'rnsa_knn',
            'scaler': self.scaler if hasattr(self.model, 'scaler') else None
        }
        
        joblib.dump(model_data, model_path)
        
        print(f"Model saved to: {model_path}")
        return model_path
    
    @classmethod
    def load(cls, model_path: str):
        """Load complete model from disk - from single file"""
        # Check if path exists
        if not os.path.exists(model_path):
            # Try adding .joblib extension
            if not model_path.endswith('.joblib'):
                model_path = f"{model_path}.joblib"
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found: {model_path}")
        
        # Load the model data
        model_data = joblib.load(model_path)
        
        # Create model instance
        model = cls(model_dir=os.path.dirname(model_path))
        
        # Restore components
        model.model = model_data['model']
        model.feature_names = model_data['feature_names']
        model.metrics = model_data['metrics']
        model.threshold = model_data['threshold']
        
        # If scaler is stored separately, restore it
        if 'scaler' in model_data and model_data['scaler'] is not None:
            model.scaler = model_data['scaler']
        elif hasattr(model.model, 'scaler'):
            model.scaler = model.model.scaler
        
        return model