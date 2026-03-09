# intrusion_detection/model.py
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.neighbors import KNeighborsClassifier
from typing import Tuple, Dict, Any, Optional, List, Union
import warnings
warnings.filterwarnings('ignore')

# ========================
# Feature alignment mapping for different datasets
# ========================
FEATURE_ALIGNMENT_MAP = {
    # UNSW-NB15 feature -> Possible names in other datasets
    'dur': ['dur', 'Flow Duration', ' Flow Duration', 'flow_duration', 'Duration', 'Dur', ' duration', 'Flow Duration'],
    'spkts': ['spkts', 'Tot Fwd Pkts', ' Total Fwd Packets', 'Total Fwd Packets', 'fwd_pkts', 'Fwd Packets', 
              'Fwd Pkts', 'Fwd Packets', 'Fwd Pkts/s', 'Tot Fwd Pkts'],
    'dpkts': ['dpkts', 'Tot Bwd Pkts', ' Total Backward Packets','Total Bwd Packets', 'bwd_pkts', 'Bwd Packets', 
              'Bwd Pkts', 'Bwd Packets', 'Bwd Pkts/s', 'Tot Bwd Pkts'],
    'sbytes': ['sbytes', 'TotLen Fwd Pkts', 'Total Length of Fwd Packets', 'fwd_bytes', 
               'Fwd Bytes', 'Fwd Len', 'Fwd Segment Size', 'TotLen Fwd Pkts'],
    'dbytes': ['dbytes', 'TotLen Bwd Pkts', ' Total Length of Bwd Packets','Total Length of Bwd Packets', 'bwd_bytes', 
               'Bwd Bytes', 'Bwd Len', 'Bwd Segment Size', 'TotLen Bwd Pkts'],
    'rate': ['rate', 'Flow Byts/s', 'Flow Bytes/s', 'flow_bytes_per_sec', 'Bytes/s', 
             'Flow Rate', 'Flow Byts/s'],
    'smean': ['smean', 'Fwd Pkt Len Mean', ' Fwd Packet Length Mean', 'Fwd Packet Length Mean', 'fwd_pkt_len_mean', 
              'Avg Fwd Segment Size', 'Fwd Pkt Len Mean'],
    'dmean': ['dmean', 'Bwd Pkt Len Mean', ' Bwd Packet Length Mean', 'Bwd Packet Length Mean', 'bwd_pkt_len_mean', 
              'Avg Bwd Segment Size', 'Bwd Pkt Len Mean'],
    'swin': ['swin', 'Init Fwd Win Byts', 'Init_Win_bytes_forward', 'Init Fwd Window Bytes', 'fwd_win', 
             'Fwd Window', 'Initial Fwd Window', 'Init Fwd Win Byts'],
    'dwin': ['dwin', 'Init Bwd Win Byts', ' Init_Win_bytes_backward', 'Init Bwd Window Bytes', 'bwd_win', 
             'Bwd Window', 'Initial Bwd Window', 'Init Bwd Win Byts'],
}

# Common feature variations with spaces and special characters
FEATURE_VARIATIONS = {
    'Flow Duration': ['dur', 'Flow Duration', ' Flow Duration', 'flow_duration', 'Duration', 'Dur', ' duration', 'Flow Duration'],
    'Tot Fwd Pkts': ['Tot Fwd Pkts', ' Total Backward Packets','Total Fwd Packets', 'tot_fwd_pkts', ' Fwd Pkts', 
                     'Fwd Packets', 'fwd_pkts', 'spkts'],
    'Tot Bwd Pkts': ['Tot Bwd Pkts', ' Total Backward Packets', 'Total Bwd Packets', 'tot_bwd_pkts', ' Bwd Pkts', 
                     'Bwd Packets', 'bwd_pkts', 'dpkts'],
    'TotLen Fwd Pkts': ['TotLen Fwd Pkts', 'Total Length of Fwd Packets', 'totlen_fwd_pkts', 
                        'Fwd Bytes', 'fwd_bytes', 'sbytes'],
    'TotLen Bwd Pkts': ['TotLen Bwd Pkts', ' Total Length of Bwd Packets', 'Total Length of Bwd Packets', 'totlen_bwd_pkts', 
                        'Bwd Bytes', 'bwd_bytes', 'dbytes'],
    'Flow Byts/s': ['Flow Byts/s', 'Flow Bytes/s', 'flow_byts_per_sec', 'Bytes/s', 'rate'],
    'Fwd Pkt Len Mean': ['Fwd Pkt Len Mean', ' Fwd Packet Length Mean', 'Fwd Packet Length Mean', 'fwd_pkt_len_mean', 
                         'Avg Fwd Segment Size', 'smean'],
    'Bwd Pkt Len Mean': ['Bwd Pkt Len Mean', ' Bwd Packet Length Mean', 'Bwd Packet Length Mean', 'bwd_pkt_len_mean', 
                         'Avg Bwd Segment Size', 'dmean'],
    'Init Fwd Win Byts': ['Init Fwd Win Byts', 'Init_Win_bytes_forward', 'Init Fwd Window Bytes', 'init_fwd_win_byts', 
                          'Fwd Window', 'swin'],
    'Init Bwd Win Byts': ['Init Bwd Win Byts', ' Init_Win_bytes_backward', 'Init Bwd Window Bytes', 'init_bwd_win_byts', 
                          'Bwd Window', 'dwin'],
}

# ========================
# Detector Class
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


# ========================
# RNSA + KNN Model
# ========================
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
        """
        self.r_s = r_s
        self.max_detectors = max_detectors
        self.k = k
        self.detectors: List[Detector] = []
        self.knn = KNeighborsClassifier(n_neighbors=k)
        self.scaler = MinMaxScaler()
        self.feature_names = None
        self.metrics = {}
        self.threshold = 0.5
        self.datasets_trained_on = []
        self.all_training_data = None
        self.all_training_labels = None
        self.expected_n_features = None

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

    def fit(self, X_train: np.ndarray, y_train: np.ndarray, dataset_name: str = None):
        """
        Train the model using both normal and abnormal samples
        
        Parameters:
        -----------
        X_train : np.ndarray
            Training features
        y_train : np.ndarray
            Training labels (0=normal, 1=abnormal)
        dataset_name : str, optional
            Name of the dataset being trained on
        """
        # Store dataset name
        if dataset_name:
            self.datasets_trained_on.append(dataset_name)

        # Set expected features on first fit
        if self.expected_n_features is None:
            self.expected_n_features = X_train.shape[1]
            print(f"First training with {self.expected_n_features} features")
        
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
        
        # Don't reset detectors - continue adding to existing ones
        if len(self.detectors) == 0:
            self.detectors = []

        for i, abnormal_sample in enumerate(abnormal_samples):
            if len(self.detectors) >= self.max_detectors:
                break

            # Check redundancy with existing detectors
            if self._is_redundant(abnormal_sample):
                continue

            # Tolerance check and radius calculation
            is_valid, radius = self._calculate_radius(abnormal_sample, normal_samples)

            if is_valid:
                # Create new detector with calculated radius
                detector = Detector(abnormal_sample.copy(), radius)
                self.detectors.append(detector)

            if (i + 1) % 100 == 0:
                print(f"  Processed {i+1}/{len(abnormal_samples)} abnormal samples, "
                      f"generated {len(self.detectors)} detectors")

        print(f"Total detectors: {len(self.detectors)}")

        # PHASE 2: Train KNN for hole remediation
        print("Phase 2: Training KNN for hole remediation...")
        
        # Store all training data for KNN retraining
        if self.all_training_data is None:
            self.all_training_data = X_train_scaled
            self.all_training_labels = y_train
        else:
            self.all_training_data = np.vstack([self.all_training_data, X_train_scaled])
            self.all_training_labels = np.hstack([self.all_training_labels, y_train])

        # Retrain KNN with all accumulated data
        self.knn.fit(self.all_training_data, self.all_training_labels)

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
        knn_proba = self.knn.predict_proba(X_scaled)

        # Get hole mask
        _, hole_mask, _ = self._nsa_classify(X)

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
            'detectors': [(det.center.tolist(), det.radius) for det in self.detectors],
            'scaler': self.scaler,
            'knn': self.knn,
            'feature_names': self.feature_names,
            'metrics': self.metrics,
            'threshold': self.threshold,
            'datasets_trained_on': self.datasets_trained_on,
            'all_training_data': self.all_training_data,
            'all_training_labels': self.all_training_labels,
            'expected_n_features': self.expected_n_features
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
        model.datasets_trained_on = model_data.get('datasets_trained_on', [])
        model.all_training_data = model_data.get('all_training_data')
        model.all_training_labels = model_data.get('all_training_labels')
        model.expected_n_features = model_data.get('expected_n_features')
        
        return model


# ========================
# Feature Alignment Utilities
# ========================
def align_features_to_target(df: pd.DataFrame, target_features: List[str]) -> pd.DataFrame:
    """
    Align DataFrame features to match target features by finding the best matches
    and handling different naming conventions (case-insensitive, spaces, etc.)
    """
    aligned_df = pd.DataFrame(index=df.index)
    original_columns = df.columns.tolist()
    
    # Create normalized versions of column names for matching
    normalized_original = {_normalize_feature_name(col): col for col in original_columns}
    
    for target_feat in target_features:
        found = False
        normalized_target = _normalize_feature_name(target_feat)
        
        # Try exact match first
        if target_feat in original_columns:
            aligned_df[target_feat] = df[target_feat]
            found = True
        # Try case-insensitive match
        elif target_feat.lower() in [col.lower() for col in original_columns]:
            matched_col = next(col for col in original_columns if col.lower() == target_feat.lower())
            aligned_df[target_feat] = df[matched_col]
            found = True
        # Try normalized match
        elif normalized_target in normalized_original:
            aligned_df[target_feat] = df[normalized_original[normalized_target]]
            found = True
        # Try mapping from feature alignment dictionary
        else:
            for possible_name in FEATURE_ALIGNMENT_MAP.get(target_feat, []):
                norm_possible = _normalize_feature_name(possible_name)
                if norm_possible in normalized_original:
                    aligned_df[target_feat] = df[normalized_original[norm_possible]]
                    found = True
                    break
        
        if not found:
            # If feature not found, fill with 0 (or use median of similar features)
            aligned_df[target_feat] = 0
    
    return aligned_df


def _normalize_feature_name(name: str) -> str:
    """
    Normalize feature name for comparison:
    - Convert to lowercase
    - Remove spaces and special characters
    - Remove common prefixes/suffixes
    """
    if not isinstance(name, str):
        return str(name)
    
    # Convert to lowercase
    normalized = name.lower()
    
    # Remove common prefixes/suffixes
    prefixes_to_remove = ['fwd', 'bwd', 'tot', 'init', 'flow', 'pkt', 'len', 'win', 'byts', 'seg']
    for prefix in prefixes_to_remove:
        normalized = normalized.replace(prefix, '')
    
    # Remove spaces, underscores, and special characters
    normalized = normalized.replace(' ', '').replace('_', '').replace('-', '').replace('/', '')
    normalized = normalized.replace('.', '').replace(',', '').replace(':', '').replace(';', '')
    
    return normalized


def find_matching_features(df: pd.DataFrame, required_features: List[str]) -> Dict[str, str]:
    """
    Find best matching column in DataFrame for each required feature
    Returns mapping of required_feature -> matched_column
    """
    matching = {}
    df_columns = df.columns.tolist()
    
    # Create normalized versions of all dataframe columns
    normalized_df_cols = {_normalize_feature_name(col): col for col in df_columns}
    
    for req_feat in required_features:
        matched = None
        normalized_req = _normalize_feature_name(req_feat)
        
        # Try exact match
        if req_feat in df_columns:
            matched = req_feat
        # Try case-insensitive match
        elif req_feat.lower() in [col.lower() for col in df_columns]:
            matched = next(col for col in df_columns if col.lower() == req_feat.lower())
        # Try normalized match
        elif normalized_req in normalized_df_cols:
            matched = normalized_df_cols[normalized_req]
        # Try mapping from alignment dictionary
        else:
            for possible_name in FEATURE_ALIGNMENT_MAP.get(req_feat, []):
                norm_possible = _normalize_feature_name(possible_name)
                if norm_possible in normalized_df_cols:
                    matched = normalized_df_cols[norm_possible]
                    break
        
        if matched:
            matching[req_feat] = matched
    
    return matching

def _get_feature_recommendations(missing_features: List[str]) -> List[str]:
    """Get recommendations for missing features"""
    recommendations = []
    
    feature_alternatives = {
        'dur': ['Flow Duration', 'Duration'],
        'spkts': ['Tot Fwd Pkts', 'Fwd Packets', 'Fwd Pkts'],
        'dpkts': ['Tot Bwd Pkts', 'Bwd Packets', 'Bwd Pkts'],
        'sbytes': ['TotLen Fwd Pkts', 'Fwd Bytes', 'Fwd Len'],
        'dbytes': ['TotLen Bwd Pkts', 'Bwd Bytes', 'Bwd Len'],
        'rate': ['Flow Byts/s', 'Bytes/s', 'Flow Rate'],
        'smean': ['Fwd Pkt Len Mean', 'Avg Fwd Segment Size'],
        'dmean': ['Bwd Pkt Len Mean', 'Avg Bwd Segment Size'],
        'swin': ['Init Fwd Win Byts', 'Fwd Window'],
        'dwin': ['Init Bwd Win Byts', 'Bwd Window']
    }
    
    for feat in missing_features:
        if feat in feature_alternatives:
            alternatives = ', '.join(f"'{alt}'" for alt in feature_alternatives[feat])
            recommendations.append(f"Feature '{feat}' could be derived from: {alternatives}")
    
    return recommendations

def analyze_dataset_compatibility(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Analyze how compatible a dataset is with the model's core features
    Returns compatibility score and detailed analysis
    """
    model = IntrusionDetectionModel()
    available_features, feature_mapping = model._find_features_in_data(df)
    
    core_features = model.CORE_FEATURES
    missing_features = [f for f in core_features if f not in available_features]
    
    compatibility_score = len(available_features) / len(core_features) * 100
    
    return {
        'compatibility_score': compatibility_score,
        'core_features': core_features,
        'available_features': available_features,
        'missing_features': missing_features,
        'feature_mapping': feature_mapping,
        'total_columns': len(df.columns),
        'recommendations': _get_feature_recommendations(missing_features)
    }

# ========================
# Complete Model Class
# ========================
class IntrusionDetectionModel:
    """Complete intrusion detection model using RNSA + KNN with feature alignment"""
    
    # Core features required by the model (10 features)
    CORE_FEATURES = ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 
                     'rate', 'smean', 'dmean', 'swin', 'dwin']
    
    def __init__(self, model_dir="saved_models"):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.metrics = {}
        self.threshold = 0.5
        self.feature_mapping = {}  # Stores mapping from model features to data features
    
    def _find_features_in_data(self, df: pd.DataFrame) -> Tuple[List[str], Dict[str, str]]:
        """
        Find which of the core features are available in the dataframe
        Returns (available_features, feature_mapping)
        """
        available = []
        mapping = {}
    
        # Normalize dataframe columns for matching
        df_columns = df.columns.tolist()
    
        print("\n[Feature Matching]")
        print(f"DataFrame has {len(df_columns)} columns")
    
        for feature in self.CORE_FEATURES:
            matched = None
        
            # Try direct match (case-sensitive)
            if feature in df_columns:
                matched = feature
            # Try case-insensitive match
            elif feature.lower() in [col.lower() for col in df_columns]:
                matched = next(col for col in df_columns if col.lower() == feature.lower())
            # Try mapping from alignment dictionary
            else:
                for possible_name in FEATURE_ALIGNMENT_MAP.get(feature, []):
                    if possible_name in df_columns:
                        matched = possible_name
                        break
                    # Try case-insensitive match for each variation
                    elif possible_name.lower() in [col.lower() for col in df_columns]:
                        matched = next(col for col in df_columns if col.lower() == possible_name.lower())
                        break
        
            if matched:
                available.append(feature)
                mapping[feature] = matched
                print(f"  ✓ '{feature}' → '{matched}'")
            else:
                print(f"  ✓ '{feature}' → '0 (filling with zeros)'")
                # Still add to available for core features, but mapping will be None
                available.append(feature)
                mapping[feature] = None
    
        return available, mapping
    
    def _normalize_name(self, name: str) -> str:
        """Normalize feature name for comparison"""
        if not isinstance(name, str):
            return str(name)
        
        # Convert to lowercase and remove common patterns
        normalized = name.lower()
        
        # Remove common prefixes/suffixes
        patterns_to_remove = ['fwd', 'bwd', 'tot', 'init', 'flow', 'pkt', 'len', 'win', 'byts', 
                             'seg', 'size', 'length', 'packet', 'bytes', 'duration', 'rate',
                             'mean', 'avg', 'total', 'initial', ' ', '_', '-', '/', '.', ',']
        
        for pattern in patterns_to_remove:
            normalized = normalized.replace(pattern, '')
        
        # Remove any remaining non-alphanumeric characters
        normalized = ''.join(c for c in normalized if c.isalnum())
        
        return normalized
    
    def preprocess_data(self, df: pd.DataFrame, fit_scaler: bool = True) -> np.ndarray:
        """
        Robust preprocessing that handles different dataset formats
        Aligns features to the 10 core features required by the model
        """
        print("\n" + "="*60)
        print("PREPROCESSING DATA")
        print("="*60)
        
        # Make a copy to avoid modifying original
        df_processed = df.copy()
        
        # Remove non-numeric columns that shouldn't be used as features
        columns_to_drop = []
        for col in df_processed.columns:
            col_lower = col.lower()
            # Drop common non-feature columns
            if any(x in col_lower for x in ['label', 'attack', 'class', 'timestamp', 'time', 
                                           'date', 'id', 'flow id', 'srcip', 'dstip', 'src_ip', 
                                           'dst_ip', 'source', 'destination']):
                if col_lower not in [f.lower() for f in self.CORE_FEATURES]:
                    columns_to_drop.append(col)
        
        if columns_to_drop:
            df_processed = df_processed.drop(columns=columns_to_drop)
            print(f"Dropped {len(columns_to_drop)} non-feature columns")
        
        # Find available features
        available_features, feature_mapping = self._find_features_in_data(df_processed)
        
        if not available_features:
            raise ValueError("No compatible features found in input data")
        
        # Store feature mapping for later use
        self.feature_mapping = feature_mapping
        
        # Create aligned dataframe with exactly the core features
        aligned_data = {}
        for feature in self.CORE_FEATURES:
            if feature in feature_mapping and feature_mapping[feature] is not None:
                # Use the mapped column
                try:
                    # Ensure we're getting numeric values
                    aligned_data[feature] = pd.to_numeric(df_processed[feature_mapping[feature]], errors='coerce')
                except:
                    aligned_data[feature] = 0
            else:
                # Feature not found, fill with zeros
                aligned_data[feature] = 0
        
        # Convert to DataFrame with correct column order
        X_aligned = pd.DataFrame(aligned_data)[self.CORE_FEATURES]
        
        print(f"\nAligned data shape: {X_aligned.shape}")
        
        # Handle missing values
        X_aligned = X_aligned.fillna(0)
        X_aligned = X_aligned.replace([np.inf, -np.inf], 0)
        
        # Ensure numeric types
        X_aligned = X_aligned.apply(pd.to_numeric, errors='coerce').fillna(0)
        
        # Convert to numpy array
        X_array = X_aligned.values.astype(np.float32)
        
        # Scale features
        if fit_scaler:
            self.scaler = MinMaxScaler()
            X_scaled = self.scaler.fit_transform(X_array)
        else:
            if self.scaler is None:
                raise ValueError("Scaler not fitted. Call fit() first.")
            X_scaled = self.scaler.transform(X_array)
        
        # Store feature names
        self.feature_names = self.CORE_FEATURES
        
        print(f"Preprocessing complete: {X_scaled.shape[0]} samples, {X_scaled.shape[1]} features")
        
        return X_scaled
    
    def fit(self, X_train: np.ndarray, y_train: np.ndarray, 
           r_s: float = 0.01, max_detectors: int = 1000, k: int = 1,
           dataset_name: str = None):
        """Train the RNSA+KNN model"""
        print("\n" + "="*60)
        print("TRAINING RNSA+KNN MODEL")
        print("="*60)
        
        # Initialize and train model
        self.model = RNSA_KNN_Model(
            r_s=r_s,
            max_detectors=max_detectors,
            k=k
        )
        
        self.model.fit(X_train, y_train, dataset_name=dataset_name)
        
        # Set threshold
        self.threshold = 0.5
        
        # Store metrics
        self.metrics = {
            'training_samples': len(X_train),
            'features_count': X_train.shape[1],
            'detectors_count': len(self.model.detectors),
            'r_s': r_s,
            'max_detectors': max_detectors,
            'k': k,
            'dataset_name': dataset_name
        }
        
        print(f"\nRNSA+KNN training complete!")
        print(f"Detectors generated: {len(self.model.detectors)}")
        print(f"Features used: {X_train.shape[1]}")
        
        return self
    
    def predict(self, X_test: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions on new data"""
        if self.model is None:
            raise ValueError("Model not trained. Call fit() first.")
        
        # Get predictions
        predictions = self.model.predict(X_test)
        
        # Get probability scores
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
        
        # Calculate ROC AUC
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
        """Save complete model to disk"""
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
            'scaler': self.scaler if hasattr(self, 'scaler') else None,
            'feature_mapping': self.feature_mapping,
            'core_features': self.CORE_FEATURES
        }
        
        joblib.dump(model_data, model_path)
        
        print(f"Model saved to: {model_path}")
        return model_path
    
    @classmethod
    def load(cls, model_path: str):
        """Load complete model from disk"""
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
        model.feature_mapping = model_data.get('feature_mapping', {})
        
        # Restore scaler
        if 'scaler' in model_data and model_data['scaler'] is not None:
            model.scaler = model_data['scaler']
        elif hasattr(model.model, 'scaler'):
            model.scaler = model.model.scaler
        
        # Set core features
        if 'core_features' in model_data:
            model.CORE_FEATURES = model_data['core_features']
        
        return model
    
    def get_feature_summary(self) -> Dict[str, Any]:
        """Get summary of features used by the model"""
        return {
            'core_features': self.CORE_FEATURES,
            'feature_mapping': self.feature_mapping,
            'feature_names': self.feature_names,
            'features_count': len(self.CORE_FEATURES) if self.CORE_FEATURES else 0
        }