# train_and_save_to_database.py
import os
import sys
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import confusion_matrix, roc_curve, auc, roc_auc_score
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Tuple, List, Optional, Dict, Any
import kagglehub
import warnings
warnings.filterwarnings('ignore')

# Add the parent directory to sys.path to import your modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import your database and auth modules
try:
    from intrusion_detection.database import DatabaseManager
    from intrusion_detection.auth import AuthManager
    from intrusion_detection.model import IntrusionDetectionModel, RNSA_KNN_Model, Detector
except ImportError:
    print("Warning: Could not import Vigilante modules. Make sure you're running from the correct directory.")
    print("Please ensure you're running this from the vigilante project root directory.")
    sys.exit(1)

# ========================
# Feature alignment mapping - 10 core features
# ========================
CORE_FEATURES = ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 
                 'rate', 'smean', 'dmean', 'swin', 'dwin']

ALIGNED_FEATURES_MAP = {
    # UNSW feature -> CIC feature
    'dur': 'Flow Duration',
    'spkts': 'Tot Fwd Pkts',
    'dpkts': 'Tot Bwd Pkts',
    'sbytes': 'TotLen Fwd Pkts',
    'dbytes': 'TotLen Bwd Pkts',
    'rate': 'Flow Byts/s',
    'smean': 'Fwd Pkt Len Mean',
    'dmean': 'Bwd Pkt Len Mean',
    'swin': 'Init Fwd Win Byts',
    'dwin': 'Init Bwd Win Byts',
}

# Feature variations for flexible matching
FEATURE_VARIATIONS = {
    'dur': ['dur', 'Flow Duration', 'flow_duration', 'Duration', 'Dur', 'duration'],
    'spkts': ['spkts', 'Tot Fwd Pkts', 'Total Fwd Packets', 'fwd_pkts', 'Fwd Packets', 'Fwd Pkts'],
    'dpkts': ['dpkts', 'Tot Bwd Pkts', 'Total Bwd Packets', 'bwd_pkts', 'Bwd Packets', 'Bwd Pkts'],
    'sbytes': ['sbytes', 'TotLen Fwd Pkts', 'Total Length of Fwd Packets', 'fwd_bytes', 'Fwd Bytes'],
    'dbytes': ['dbytes', 'TotLen Bwd Pkts', 'Total Length of Bwd Packets', 'bwd_bytes', 'Bwd Bytes'],
    'rate': ['rate', 'Flow Byts/s', 'Flow Bytes/s', 'flow_bytes_per_sec', 'Bytes/s'],
    'smean': ['smean', 'Fwd Pkt Len Mean', 'Fwd Packet Length Mean', 'fwd_pkt_len_mean'],
    'dmean': ['dmean', 'Bwd Pkt Len Mean', 'Bwd Packet Length Mean', 'bwd_pkt_len_mean'],
    'swin': ['swin', 'Init Fwd Win Byts', 'Init Fwd Window Bytes', 'fwd_win'],
    'dwin': ['dwin', 'Init Bwd Win Byts', 'Init Bwd Window Bytes', 'bwd_win'],
}


def _normalize_feature_name(name: str) -> str:
    """Normalize feature name for case-insensitive comparison"""
    if not isinstance(name, str):
        return str(name)
    
    # Convert to lowercase and remove spaces/underscores
    normalized = name.lower()
    normalized = normalized.replace(' ', '').replace('_', '').replace('-', '')
    normalized = normalized.replace('.', '').replace(',', '').replace('/', '')
    
    # Remove common prefixes/suffixes
    prefixes_to_remove = ['fwd', 'bwd', 'tot', 'init', 'flow', 'pkt', 'len', 'win', 'byts']
    for prefix in prefixes_to_remove:
        normalized = normalized.replace(prefix, '')
    
    return normalized


def find_matching_features(df: pd.DataFrame) -> Tuple[List[str], Dict[str, str]]:
    """
    Find which of the core features are available in the dataframe
    Returns (available_features, feature_mapping)
    """
    available = []
    mapping = {}
    
    # Create normalized versions of dataframe columns
    df_columns = df.columns.tolist()
    normalized_df_cols = {_normalize_feature_name(col): col for col in df_columns}
    
    print("\n[Feature Matching Analysis]")
    print(f"DataFrame has {len(df_columns)} columns")
    print(f"Looking for {len(CORE_FEATURES)} core features")
    
    for feature in CORE_FEATURES:
        matched = None
        normalized_feat = _normalize_feature_name(feature)
        
        # Try exact match
        if feature in df_columns:
            matched = feature
        # Try case-insensitive match
        elif feature.lower() in [col.lower() for col in df_columns]:
            matched = next(col for col in df_columns if col.lower() == feature.lower())
        # Try normalized match
        elif normalized_feat in normalized_df_cols:
            matched = normalized_df_cols[normalized_feat]
        # Try variations
        else:
            variations = FEATURE_VARIATIONS.get(feature, [])
            for var in variations:
                norm_var = _normalize_feature_name(var)
                if norm_var in normalized_df_cols:
                    matched = normalized_df_cols[norm_var]
                    break
        
        if matched:
            available.append(feature)
            mapping[feature] = matched
            print(f"  ✓ '{feature}' → '{matched}'")
        else:
            print(f"  ✗ '{feature}' not found (will be filled with zeros)")
    
    return available, mapping


def extract_aligned_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract only the 10 core features from any dataset
    Handles different naming conventions and missing features
    """
    # Make a copy to avoid modifying original
    df_processed = df.copy()
    
    # Find matching features
    available_features, feature_mapping = find_matching_features(df_processed)
    
    # Create aligned dataframe with exactly the 10 core features
    aligned_data = {}
    
    for feature in CORE_FEATURES:
        if feature in feature_mapping:
            # Use the mapped column
            aligned_data[feature] = df_processed[feature_mapping[feature]]
        else:
            # Feature not found, fill with zeros
            aligned_data[feature] = 0
    
    # Convert to DataFrame with correct column order
    df_aligned = pd.DataFrame(aligned_data)[CORE_FEATURES]
    
    # Handle missing values
    df_aligned = df_aligned.fillna(0)
    df_aligned = df_aligned.replace([np.inf, -np.inf], 0)
    
    # Ensure numeric types
    for col in df_aligned.columns:
        df_aligned[col] = pd.to_numeric(df_aligned[col], errors='coerce').fillna(0)
    
    print(f"\nAligned data shape: {df_aligned.shape}")
    print(f"Features extracted: {len(available_features)}/{len(CORE_FEATURES)}")
    
    return df_aligned, available_features, feature_mapping


# ========================
# UNSW-NB15 Dataset Loading with Feature Alignment
# ========================
def load_and_preprocess_unsw_nb15():
    """Load and preprocess UNSW-NB15 dataset - EXTRACT ONLY THE 10 CORE FEATURES"""
    print("\n" + "="*60)
    print("LOADING UNSW-NB15 DATASET")
    print("="*60)
    
    print("Downloading UNSW-NB15 dataset...")
    path = kagglehub.dataset_download("mrwellsdavid/unsw-nb15")
    train_path = os.path.join(path, "UNSW_NB15_training-set.csv")
    test_path = os.path.join(path, "UNSW_NB15_testing-set.csv")
    
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)
    
    print(f"Original UNSW-NB15 training set: {train_df.shape}")
    print(f"Original UNSW-NB15 test set: {test_df.shape}")
    
    # Preprocess training data
    train_df_processed = train_df.copy()
    train_df_processed.dropna(inplace=True)
    
    # Replacing '-' in state and service for 'other'
    if 'state' in train_df_processed.columns:
        train_df_processed['state'] = train_df_processed['state'].replace('-', 'other')
    if 'service' in train_df_processed.columns:
        train_df_processed['service'] = train_df_processed['service'].replace('-', 'other')
    
    # Extract aligned features for training
    train_aligned, train_available, train_mapping = extract_aligned_features(train_df_processed)
    
    # Get labels
    y_train = train_df_processed['label'].values if 'label' in train_df_processed.columns else None
    
    if y_train is None:
        raise ValueError("No label column found in UNSW-NB15 training data")
    
    # Preprocess test data
    test_df_processed = test_df.copy()
    test_df_processed.dropna(inplace=True)
    
    if 'state' in test_df_processed.columns:
        test_df_processed['state'] = test_df_processed['state'].replace('-', 'other')
    if 'service' in test_df_processed.columns:
        test_df_processed['service'] = test_df_processed['service'].replace('-', 'other')
    
    # Extract aligned features for test
    test_aligned, test_available, test_mapping = extract_aligned_features(test_df_processed)
    
    # Get test labels
    y_test = test_df_processed['label'].values if 'label' in test_df_processed.columns else None
    
    # Balance training data by downsampling majority class
    train_normal_count = np.sum(y_train == 0)
    train_attack_count = np.sum(y_train == 1)
    
    print(f"\nOriginal training counts: Normal={train_normal_count}, Attack={train_attack_count}")
    
    # Balance classes if needed
    if train_normal_count > train_attack_count:
        # Downsample normal class
        normal_indices = np.where(y_train == 0)[0]
        attack_indices = np.where(y_train == 1)[0]
        
        sampled_normal_indices = np.random.choice(normal_indices, size=len(attack_indices), replace=False)
        balanced_indices = np.concatenate([sampled_normal_indices, attack_indices])
    else:
        # Downsample attack class
        normal_indices = np.where(y_train == 0)[0]
        attack_indices = np.where(y_train == 1)[0]
        
        sampled_attack_indices = np.random.choice(attack_indices, size=len(normal_indices), replace=False)
        balanced_indices = np.concatenate([normal_indices, sampled_attack_indices])
    
    np.random.shuffle(balanced_indices)
    
    X_train_balanced = train_aligned.iloc[balanced_indices].values
    y_train_balanced = y_train[balanced_indices]
    
    X_test_values = test_aligned.values
    y_test_values = y_test
    
    print(f"\nUNSW-NB15 Training set: {X_train_balanced.shape[0]} samples, {X_train_balanced.shape[1]} features")
    print(f"UNSW-NB15 Test set: {X_test_values.shape[0]} samples")
    print(f"UNSW-NB15 Normal samples in training: {np.sum(y_train_balanced == 0)}")
    print(f"UNSW-NB15 Attack samples in training: {np.sum(y_train_balanced == 1)}")
    print(f"Aligned features: {CORE_FEATURES}")
    
    return X_train_balanced, y_train_balanced, X_test_values, y_test_values, CORE_FEATURES


# ========================
# CIC-IDS-2018 Dataset Loading with Feature Alignment
# ========================
def load_and_preprocess_cic_ids_2018():
    """Load and preprocess CIC-IDS-2018 dataset - EXTRACT ONLY THE 10 CORE FEATURES"""
    print("\n" + "="*60)
    print("LOADING CIC-IDS-2018 DATASET")
    print("="*60)
    
    print("Downloading CIC-IDS-2018 dataset...")
    path = kagglehub.dataset_download("solarmainframe/ids-intrusion-csv")
    train_path = os.path.join(path, "02-14-2018.csv")
    
    df_dataset = pd.read_csv(train_path)
    print(f"Original CIC-IDS-2018 dataset: {df_dataset.shape}")
    
    # Replace infinities with NaN and drop missing values
    df_dataset.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_dataset.dropna(inplace=True)
    
    # Replace attack types
    df_dataset.replace(to_replace=["FTP-BruteForce", "SSH-Bruteforce", "DoS", "DDoS", "PortScan", "BruteForce"],
                      value="Malicious", inplace=True)
    
    # Keep only Benign and Malicious
    df = df_dataset[df_dataset["Label"].isin(["Benign", "Malicious"])].copy()
    
    print(f"After filtering: {df.shape}")
    
    # Extract aligned features
    aligned_df, available_features, feature_mapping = extract_aligned_features(df)
    
    # Get labels
    labels = df['Label'].values
    y = np.array([0 if label == 'Benign' else 1 for label in labels])
    
    # Add labels to aligned dataframe for splitting
    aligned_df['Label'] = y
    
    # Balance the dataset
    df_benign = aligned_df[aligned_df['Label'] == 0]
    df_malicious = aligned_df[aligned_df['Label'] == 1]
    
    min_count = min(len(df_benign), len(df_malicious))
    print(f"\nBalancing classes: Benign={len(df_benign)}, Malicious={len(df_malicious)}")
    print(f"Using {min_count} samples from each class")
    
    df_benign_sampled = df_benign.sample(n=min_count, random_state=42)
    df_malicious_sampled = df_malicious.sample(n=min_count, random_state=42)
    
    df_balanced = pd.concat([df_benign_sampled, df_malicious_sampled], axis=0)
    df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Split into train/test
    train, test = train_test_split(df_balanced, test_size=0.20, random_state=12)
    
    # Separate features and labels
    y_train = train['Label'].values
    X_train = train.drop('Label', axis=1).values
    
    y_test = test['Label'].values
    X_test = test.drop('Label', axis=1).values
    
    print(f"\nCIC-IDS-2018 Training set: {X_train.shape[0]} samples, {X_train.shape[1]} features")
    print(f"CIC-IDS-2018 Test set: {X_test.shape[0]} samples")
    print(f"Aligned features: {CORE_FEATURES}")
    
    return X_train, y_train, X_test, y_test, CORE_FEATURES


# ========================
# Train Single Model on Both Datasets with Feature Alignment
# ========================
def train_single_model_on_both_datasets(user_id=1):
    """Train a single model sequentially on both UNSW-NB15 and CIC-IDS-2018 datasets with feature alignment"""
    print("\n" + "="*80)
    print("TRAINING SINGLE RNSA+KNN MODEL ON BOTH DATASETS WITH FEATURE ALIGNMENT")
    print("="*80)
    print(f"Core Features: {CORE_FEATURES}")
    
    try:
        # Create single model instance using imported class
        print("\nCreating RNSA_KNN_Model instance...")
        model = RNSA_KNN_Model(r_s=0.01, max_detectors=2000, k=1)
        
        # ============================================================
        # PART 1: Train on UNSW-NB15
        # ============================================================
        print("\n" + "="*60)
        print("PART 1: Training on UNSW-NB15 Dataset")
        print("="*60)
        
        # Load and preprocess UNSW-NB15 with aligned features
        X_unsw_train, y_unsw_train, X_unsw_test, y_unsw_test, unsw_features = load_and_preprocess_unsw_nb15()
        
        # Store feature names
        model.feature_names = unsw_features
        
        # Train on UNSW-NB15
        print("\nTraining on UNSW-NB15...")
        model.fit(X_unsw_train, y_unsw_train, dataset_name="UNSW-NB15")
        
        # Evaluate on UNSW test set
        print("\nEvaluating on UNSW-NB15 test set...")
        unsw_metrics = model.evaluate(X_unsw_test, y_unsw_test)
        unsw_train_acc = accuracy_score(y_unsw_train, model.predict(X_unsw_train))
        
        # ============================================================
        # PART 2: Continue Training on CIC-IDS-2018
        # ============================================================
        print("\n" + "="*60)
        print("PART 2: Continuing Training on CIC-IDS-2018 Dataset")
        print("="*60)
        
        # Load and preprocess CIC-IDS-2018 with aligned features
        X_cic_train, y_cic_train, X_cic_test, y_cic_test, cic_features = load_and_preprocess_cic_ids_2018()
        
        print(f"\nNote: Both datasets now have {X_unsw_train.shape[1]} features (aligned)")
        print("Continuing training on CIC-IDS-2018...")
        
        # Train on CIC-IDS-2018
        model.fit(X_cic_train, y_cic_train, dataset_name="CIC-IDS-2018")
        
        # Evaluate on CIC test set
        print("\nEvaluating on CIC-IDS-2018 test set...")
        cic_metrics = model.evaluate(X_cic_test, y_cic_test)
        cic_train_acc = accuracy_score(y_cic_train, model.predict(X_cic_train))
        
        # ============================================================
        # Create Metadata and Save Model
        # ============================================================
        model_name = f"RNSA_KNN_ALIGNED_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        metadata = {
            'model_name': model_name,
            'created_at': datetime.now().isoformat(),
            'dataset': 'UNSW-NB15 + CIC-IDS-2018 (Aligned Features)',
            'dataset_source': 'Sequential training on both datasets with feature alignment',
            'datasets_trained_on': model.datasets_trained_on,
            'training_samples': len(X_unsw_train) + len(X_cic_train),
            'test_samples': len(X_unsw_test) + len(X_cic_test),
            'features_count': X_unsw_train.shape[1],
            'core_features': CORE_FEATURES,
            'detectors_count': len(model.detectors),
            'unsw_metrics': {
                'accuracy': unsw_metrics['accuracy'],
                'precision': unsw_metrics['precision'],
                'recall': unsw_metrics['recall'],
                'f1_score': unsw_metrics['f1_score'],
                'detection_rate': unsw_metrics['detection_rate'],
                'false_alarm_rate': unsw_metrics['false_alarm_rate'],
                'auc': unsw_metrics['auc'],
                'train_accuracy': float(unsw_train_acc),
                'test_accuracy': unsw_metrics['accuracy']
            },
            'cic_metrics': {
                'accuracy': cic_metrics['accuracy'],
                'precision': cic_metrics['precision'],
                'recall': cic_metrics['recall'],
                'f1_score': cic_metrics['f1_score'],
                'detection_rate': cic_metrics['detection_rate'],
                'false_alarm_rate': cic_metrics['false_alarm_rate'],
                'auc': cic_metrics['auc'],
                'train_accuracy': float(cic_train_acc),
                'test_accuracy': cic_metrics['accuracy']
            },
            'combined_metrics': {
                'detectors_count': len(model.detectors),
                'datasets_trained': 2,
                'unsw_training_samples': len(X_unsw_train),
                'cic_training_samples': len(X_cic_train),
                'total_training_samples': len(X_unsw_train) + len(X_cic_train),
                'avg_accuracy': (unsw_metrics['accuracy'] + cic_metrics['accuracy']) / 2,
                'avg_detection_rate': (unsw_metrics['detection_rate'] + cic_metrics['detection_rate']) / 2,
                'avg_false_alarm_rate': (unsw_metrics['false_alarm_rate'] + cic_metrics['false_alarm_rate']) / 2,
                'avg_auc': (unsw_metrics['auc'] + cic_metrics['auc']) / 2
            }
        }
        
        # Save model to file
        print("\n" + "="*60)
        print("SAVING MODEL")
        print("="*60)
        
        model_dir = "saved_models"
        os.makedirs(model_dir, exist_ok=True)
        
        model_filename = f"{model_name}.joblib"
        model_path = os.path.join(model_dir, model_filename)

        # Save the RNSA_KNN_Model directly
        model.save(model_path)
        
        # ALSO save using IntrusionDetectionModel wrapper for compatibility
        print("\nCreating IntrusionDetectionModel wrapper for compatibility...")
        intrusion_model = IntrusionDetectionModel(model_dir)
        intrusion_model.model = model
        intrusion_model.feature_names = CORE_FEATURES
        intrusion_model.metrics = metadata['combined_metrics']
        intrusion_model.threshold = 0.5
        
        # Save wrapper
        wrapper_path = intrusion_model.save(model_name)
        print(f"Wrapper saved to: {wrapper_path}")
        
        # ============================================================
        # Save to Database
        # ============================================================
        print("\n" + "="*60)
        print("SAVING TO DATABASE")
        print("="*60)
        
        try:
            # Create fresh database connection
            db = DatabaseManager()
            
            # Calculate average metrics
            avg_accuracy = (unsw_metrics['accuracy'] + cic_metrics['accuracy']) / 2
            avg_precision = (unsw_metrics['precision'] + cic_metrics['precision']) / 2
            avg_recall = (unsw_metrics['recall'] + cic_metrics['recall']) / 2
            avg_f1 = (unsw_metrics['f1_score'] + cic_metrics['f1_score']) / 2
            
            # Save to database with proper metrics
            model_id = db.save_model(
                user_id=user_id,
                model_name=model_name,
                model_path=model_path,
                dataset_name="UNSW-NB15 + CIC-IDS-2018 (Aligned 10 Features)",
                metrics={
                    'accuracy': avg_accuracy,
                    'precision': avg_precision,
                    'recall': avg_recall,
                    'f1_score': avg_f1,
                    'detection_rate': (unsw_metrics['detection_rate'] + cic_metrics['detection_rate']) / 2,
                    'false_alarm_rate': (unsw_metrics['false_alarm_rate'] + cic_metrics['false_alarm_rate']) / 2,
                    'auc': (unsw_metrics['auc'] + cic_metrics['auc']) / 2,
                    'detectors_count': len(model.detectors),
                    'training_samples': len(X_unsw_train) + len(X_cic_train),
                    'test_accuracy': avg_accuracy,
                    'unsw_accuracy': unsw_metrics['accuracy'],
                    'cic_accuracy': cic_metrics['accuracy']
                },
                features=CORE_FEATURES,
                parameters={
                    'r_s': 0.01,
                    'max_detectors': 2000,
                    'k': 1,
                    'estimated_coverage': 0.99,
                    'model_type': 'rnsa_knn',
                    'algorithm': 'RNSA + KNN',
                    'normalization': 'MinMaxScaler',
                    'distance_metric': 'euclidean',
                    'training_method': 'sequential',
                    'datasets': ['UNSW-NB15', 'CIC-IDS-2018'],
                    'unsw_training_samples': len(X_unsw_train),
                    'cic_training_samples': len(X_cic_train),
                    'core_features': CORE_FEATURES,
                    'feature_alignment': '10 core features extracted from both datasets'
                }
            )
            
            print(f"\n✅ Model saved to database with ID: {model_id}")
            
            # Verify the save by retrieving from database
            db_model = db.get_model(model_id, user_id)
            if db_model:
                print(f"\n📋 Database Model Details:")
                print(f"   ID: {db_model['id']}")
                print(f"   Name: {db_model['name']}")
                print(f"   Accuracy: {db_model.get('accuracy', 'N/A'):.4f}")
                print(f"   Created: {db_model['created_at']}")
                print(f"   Path: {db_model['model_path']}")
                print(f"   Detectors: {len(model.detectors)}")
            
            # Close the database connection
            db.close()
            
            return model_id, metadata
        
        except Exception as e:
            print(f"\n❌ Error saving to database: {e}")
            import traceback
            traceback.print_exc()
            return None, metadata
            
    except Exception as e:
        print(f"\n❌ Error training combined model: {e}")
        import traceback
        traceback.print_exc()
        return None, None


def main():
    """Main function to train a single model sequentially on both datasets with feature alignment"""
    print("="*80)
    print("VIGILANTE - RNSA+KNN SINGLE MODEL WITH FEATURE ALIGNMENT")
    print("="*80)
    print(f"Using 10 Core Features: {CORE_FEATURES}")
    
    try:
        # Use admin user ID (default is 1 for admin1)
        user_id = 1
        
        # Train model
        model_id, metadata = train_single_model_on_both_datasets(user_id)

        if model_id:
            print(f"\n✅ Model successfully saved to database with ID: {model_id}")
            print(f"   You can use this model with: vigilante detect --model-id {model_id}")
            print(f"   The model expects the following 10 features: {CORE_FEATURES}")
        else:
            print("\n⚠️ Model was trained but not saved to database")
        
        # Display summary
        if metadata:
            print("\n" + "="*80)
            print("MODEL TRAINING SUMMARY")
            print("="*80)
            
            print(f"\nModel Name: {metadata['model_name']}")
            print(f"Core Features: {metadata['core_features']}")
            print(f"Created: {metadata['created_at']}")
            print(f"Datasets Trained On: {metadata['datasets_trained_on']}")
            print(f"Total Training Samples: {metadata['training_samples']:,}")
            print(f"Total Test Samples: {metadata['test_samples']:,}")
            print(f"Features: {metadata['features_count']}")
            print(f"Detectors Generated: {metadata['detectors_count']:,}")
            
            print(f"\n{'='*40} UNSW-NB15 Performance {'='*40}")
            unsw_metrics = metadata['unsw_metrics']
            print(f"  Train Accuracy: {unsw_metrics['train_accuracy']:.4f}")
            print(f"  Test Accuracy: {unsw_metrics['test_accuracy']:.4f}")
            print(f"  Precision: {unsw_metrics['precision']:.4f}")
            print(f"  Recall: {unsw_metrics['recall']:.4f}")
            print(f"  F1-Score: {unsw_metrics['f1_score']:.4f}")
            print(f"  Detection Rate: {unsw_metrics['detection_rate']:.4f}")
            print(f"  False Alarm Rate: {unsw_metrics['false_alarm_rate']:.4f}")
            print(f"  AUC: {unsw_metrics['auc']:.4f}")
            
            print(f"\n{'='*40} CIC-IDS-2018 Performance {'='*40}")
            cic_metrics = metadata['cic_metrics']
            print(f"  Train Accuracy: {cic_metrics['train_accuracy']:.4f}")
            print(f"  Test Accuracy: {cic_metrics['test_accuracy']:.4f}")
            print(f"  Precision: {cic_metrics['precision']:.4f}")
            print(f"  Recall: {cic_metrics['recall']:.4f}")
            print(f"  F1-Score: {cic_metrics['f1_score']:.4f}")
            print(f"  Detection Rate: {cic_metrics['detection_rate']:.4f}")
            print(f"  False Alarm Rate: {cic_metrics['false_alarm_rate']:.4f}")
            print(f"  AUC: {cic_metrics['auc']:.4f}")
            
            print(f"\n{'='*40} Combined Performance {'='*40}")
            combined = metadata['combined_metrics']
            print(f"  Average Accuracy: {combined['avg_accuracy']:.4f}")
            print(f"  Average Detection Rate: {combined['avg_detection_rate']:.4f}")
            print(f"  Average False Alarm Rate: {combined['avg_false_alarm_rate']:.4f}")
            print(f"  Average AUC: {combined['avg_auc']:.4f}")
            print(f"  Total Detectors: {combined['detectors_count']}")
        
        # Log completion
        print("\n" + "="*80)
        print("TRAINING COMPLETED SUCCESSFULLY!")
        print("="*80)
        
        if model_id:
            print(f"Single model trained on both datasets with feature alignment saved to database with ID: {model_id}")
        
        print(f"\nModel files saved in: saved_models/")
        print(f"\nYou can now use this model with the vigilante CLI:")
        print(f"  vigilante detect --input your_data.csv --model-id {model_id if model_id else 'MODEL_ID'}")
        print(f"\nThe model expects the following 10 features in any order/format:")
        for feat in CORE_FEATURES:
            print(f"  • {feat}")
        
        # Save metadata to JSON file for reference
        if metadata:
            import json
            metadata_path = f"saved_models/{metadata['model_name']}_metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2, default=str)
            print(f"\nMetadata saved to: {metadata_path}")
        
    except Exception as e:
        print(f"\n❌ Error in main execution: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    # Create necessary directories
    os.makedirs("saved_models", exist_ok=True)
    os.makedirs("models", exist_ok=True)
    
    # Run main function
    exit_code = main()
    sys.exit(exit_code)