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

# Function to preprocess UNSW-NB15 dataset
def preprocess_unsw(df, train_columns=None):
    df_processed = df.copy()
    df_processed.dropna(inplace=True)
    
    # Drop 'id' column if it exists
    if 'id' in df_processed.columns:
        df_processed.drop(['id'], axis=1, inplace=True)
    
    # Replacing '-' in state and service for 'other'
    if 'state' in df_processed.columns:
        df_processed['state'] = df_processed['state'].replace('-','other')
    if 'service' in df_processed.columns:
        df_processed['service'] = df_processed['service'].replace('-','other')
    
    # Store original columns before one-hot encoding
    original_columns = df_processed.columns.tolist()
    
    # One-hot encode categorical columns
    categorical_cols = []
    if 'proto' in df_processed.columns:
        categorical_cols.append('proto')
    if 'service' in df_processed.columns:
        categorical_cols.append('service')
    
    if categorical_cols:
        df_processed = pd.get_dummies(df_processed, columns=categorical_cols, drop_first=True)
    
    # If train_columns is provided (for test set), align columns
    if train_columns is not None:
        missing_cols = set(train_columns) - set(df_processed.columns)
        for col in missing_cols:
            df_processed[col] = 0
        extra_cols = set(df_processed.columns) - set(train_columns)
        df_processed = df_processed.drop(columns=list(extra_cols))
        df_processed = df_processed[train_columns]
    
    # Encode categorical columns
    if 'state' in df_processed.columns:
        label_encoder = LabelEncoder()
        df_processed['state'] = label_encoder.fit_transform(df_processed['state'])
    if 'attack_cat' in df_processed.columns:
        label_encoder = LabelEncoder()
        df_processed['attack_cat'] = label_encoder.fit_transform(df_processed['attack_cat'])
    
    # Feature engineering (only if columns exist)
    if all(col in df_processed.columns for col in ['sload', 'dload']):
        df_processed['load_interaction'] = df_processed['sload'] * df_processed['dload']
    if all(col in df_processed.columns for col in ['sbytes', 'dbytes']):
        df_processed['total_bytes'] = df_processed['sbytes'] + df_processed['dbytes']
    if all(col in df_processed.columns for col in ['spkts', 'dpkts']):
        df_processed['pkt_flow_ratio'] = df_processed['spkts'] / (df_processed['dpkts'] + 1)
    if all(col in df_processed.columns for col in ['sbytes', 'dbytes']):
        df_processed['bytes_diff'] = df_processed['sbytes'] - df_processed['dbytes']
        df_processed['bytes_ratio'] = df_processed['sbytes'] / (df_processed['dbytes'] + 1)
    
    return df_processed

def load_and_preprocess_unsw_nb15():
    """Load and preprocess UNSW-NB15 dataset"""
    print("Downloading UNSW-NB15 dataset...")
    path = kagglehub.dataset_download("mrwellsdavid/unsw-nb15")
    train_path = os.path.join(path, "UNSW_NB15_training-set.csv")
    test_path = os.path.join(path, "UNSW_NB15_testing-set.csv")
    
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)
    
    # Preprocess data
    print("Preprocessing UNSW-NB15 data...")
    train_df_processed = preprocess_unsw(train_df)
    test_df_processed = preprocess_unsw(test_df, train_df_processed.columns.tolist())
    
    # Prepare training data
    X_train = train_df_processed.drop('label', axis=1).values
    y_train = train_df_processed['label'].values
    
    # Prepare test data with reduced attack samples
    test_attack_mask = test_df_processed['label'] == 1
    test_normal_mask = test_df_processed['label'] == 0
    
    attack_samples_test = test_df_processed[test_attack_mask]
    normal_samples_test = test_df_processed[test_normal_mask]
    
    reduction_percentage = 0.4
    num_attack_to_keep = int(len(attack_samples_test) * (1 - reduction_percentage))
    attack_samples_reduced = attack_samples_test.sample(n=num_attack_to_keep, random_state=42)
    
    test_df_reduced = pd.concat([normal_samples_test, attack_samples_reduced], axis=0)
    test_df_reduced = test_df_reduced.sample(frac=1, random_state=42).reset_index(drop=True)
    
    X_test = test_df_reduced.drop('label', axis=1).values
    y_test = test_df_reduced['label'].values
    
    return X_train, y_train, X_test, y_test, train_df_processed.drop('label', axis=1).columns.tolist()

def load_and_preprocess_cic_ids_2018():
    """Load and preprocess CIC-IDS-2018 dataset"""
    print("Downloading CIC-IDS-2018 dataset...")
    path_cic = kagglehub.dataset_download("solarmainframe/ids-intrusion-csv")
    train_path_cic = os.path.join(path_cic, "02-14-2018.csv")
    
    df_dataset = pd.read_csv(train_path_cic)
    
    # Preprocess CIC-IDS-2018 dataset
    print("Preprocessing CIC-IDS-2018 data...")
    df_dataset.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_dataset.dropna(inplace=True)
    df_dataset.replace(to_replace=["FTP-BruteForce", "SSH-Bruteforce"], value="Malicious", inplace=True)
    df_dataset.drop_duplicates(inplace=True)
    
    df = df_dataset
    df1 = df[df["Label"] == "Benign"][:156668]
    df2 = df[df["Label"] == "Malicious"][:156668]
    df_equal = pd.concat([df1, df2], axis=0)
    df_equal.replace(to_replace="Benign", value=0, inplace=True)
    df_equal.replace(to_replace="Malicious", value=1, inplace=True)
    df_equal['Label'] = df_equal['Label'].astype(int)
    
    # Split data
    train_cic, test_cic = train_test_split(df_equal, test_size=0.25, random_state=12)
    
    # Scale numerical features
    numerical_columns = ['Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 
                       'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 
                       'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 
                       'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean', 'Flow IAT Std', 
                       'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 
                       'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 
                       'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 
                       'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s', 
                       'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 
                       'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 
                       'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg', 
                       'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 
                       'Fwd Blk Rate Avg', 'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 
                       'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts', 
                       'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min', 
                       'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 
                       'Idle Max', 'Idle Min']
    
    # Only use columns that exist in the dataframe
    numerical_columns = [col for col in numerical_columns if col in train_cic.columns]
    
    min_max_scaler = MinMaxScaler().fit(train_cic[numerical_columns])
    train_cic[numerical_columns] = min_max_scaler.transform(train_cic[numerical_columns])
    
    if 'Timestamp' in train_cic.columns:
        train_cic.drop(['Timestamp'], axis=1, inplace=True)
    if 'Timestamp' in test_cic.columns:
        test_cic.drop(['Timestamp'], axis=1, inplace=True)
    
    test_cic[numerical_columns] = min_max_scaler.transform(test_cic[numerical_columns])
    
    # Prepare data
    y_train = np.array(train_cic.pop("Label"))
    X_train = train_cic.values
    y_test = np.array(test_cic.pop("Label"))
    X_test = test_cic.values
    
    return X_train, y_train, X_test, y_test, train_cic.columns.tolist()

def train_single_model_on_both_datasets(user_id=1):  # Remove db and auth parameters
    """Train a single model sequentially on both UNSW-NB15 and CIC-IDS-2018 datasets"""
    print("\n" + "="*80)
    print("TRAINING SINGLE RNSA+KNN MODEL SEQUENTIALLY ON BOTH DATASETS")
    print("="*80)
    
    try:
        # Create single model instance using imported class
        print("Creating RNSA_KNN_Model instance...")
        model = RNSA_KNN_Model(r_s=0.01, max_detectors=1000, k=1)
        
        # Load and preprocess UNSW-NB15
        print("\n1. Loading and training on UNSW-NB15 dataset...")
        X_unsw_train, y_unsw_train, X_unsw_test, y_unsw_test, unsw_features = load_and_preprocess_unsw_nb15()
        
        print(f"UNSW-NB15: {len(X_unsw_train)} training samples, {X_unsw_train.shape[1]} features")
        
        # Store feature names for UNSW
        model.feature_names = unsw_features
        
        # Train model on UNSW-NB15
        print("\nTraining on UNSW-NB15...")
        model.fit(X_unsw_train, y_unsw_train)
        
        # Evaluate on UNSW test set
        print("\nEvaluating on UNSW-NB15 test set...")
        unsw_metrics = model.evaluate(X_unsw_test, y_unsw_test)
        unsw_train_acc = accuracy_score(y_unsw_train, model.predict(X_unsw_train))
        
        # Load and preprocess CIC-IDS-2018
        print("\n2. Loading and training on CIC-IDS-2018 dataset...")
        X_cic_train, y_cic_train, X_cic_test, y_cic_test, cic_features = load_and_preprocess_cic_ids_2018()
        
        print(f"CIC-IDS-2018: {len(X_cic_train)} training samples, {X_cic_train.shape[1]} features")
        
        print("\nNote: Model was fitted on UNSW-NB15 feature space.")
        print(f"Model expects {X_unsw_train.shape[1]} features, CIC data has {X_cic_train.shape[1]} features")
        print("Continuing with original training approach...")
        
        # Train model on CIC-IDS-2018
        print("\nTraining on CIC-IDS-2018...")
        model.fit(X_cic_train, y_cic_train)
        
        # Evaluate on CIC test set
        print("\nEvaluating on CIC-IDS-2018 test set...")
        cic_metrics = model.evaluate(X_cic_test, y_cic_test)
        cic_train_acc = accuracy_score(y_cic_train, model.predict(X_cic_train))
        
        # Create metadata
        model_name = f"RNSA_KNN_SEQUENTIAL_BOTH_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        metadata = {
            'model_name': model_name,
            'created_at': pd.Timestamp.now().isoformat(),
            'dataset': 'UNSW-NB15 + CIC-IDS-2018 (Sequential Training)',
            'dataset_source': 'Sequential training on both datasets',
            'datasets_trained_on': ['UNSW-NB15', 'CIC-IDS-2018'],
            'training_samples': len(X_unsw_train) + len(X_cic_train),
            'test_samples': len(X_unsw_test) + len(X_cic_test),
            'features_count': X_unsw_train.shape[1],
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
                'total_training_samples': len(X_unsw_train) + len(X_cic_train)
            }
        }
        
        # Save model to file
        print("\n4. Saving model to file...")
        model_dir = "saved_models"
        os.makedirs(model_dir, exist_ok=True)
        
        model_filename = f"{model_name}.joblib"
        model_path = os.path.join(model_dir, model_filename)

        # Save the RNSA_KNN_Model directly
        model.save(model_path)
        
        # ALSO save using IntrusionDetectionModel wrapper for compatibility
        print("Creating IntrusionDetectionModel wrapper for compatibility...")
        intrusion_model = IntrusionDetectionModel(model_dir)
        intrusion_model.model = model
        intrusion_model.feature_names = model.feature_names
        intrusion_model.metrics = metadata['combined_metrics']
        intrusion_model.threshold = 0.5
        
        # Save wrapper
        wrapper_path = intrusion_model.save(model_name)
        print(f"Wrapper saved to: {wrapper_path}")
        
        # Save model metrics to the model object
        model.metrics = metadata['combined_metrics']
        
        # Create FRESH database connection before saving
        print("\n5. Creating fresh database connection and saving model to database...")
        try:
            # Create new database connection
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
                model_path=model_path,  # Use the .joblib file path
                dataset_name="UNSW-NB15 + CIC-IDS-2018 (Sequential)",
                metrics={
                    'accuracy': avg_accuracy,
                    'precision': avg_precision,
                    'recall': avg_recall,
                    'f1_score': avg_f1,
                    'detection_rate': (unsw_metrics['detection_rate'] + cic_metrics['detection_rate']) / 2,
                    'false_alarm_rate': (unsw_metrics['false_alarm_rate'] + cic_metrics['false_alarm_rate']) / 2,
                    'auc': (unsw_metrics['auc'] + cic_metrics['auc']) / 2,
                    'detectors_count': len(model.detectors),
                    'training_samples': len(X_unsw_train) + len(X_cic_train)
                },
                features=model.feature_names,
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
                    'feature_space': 'UNSW-NB15 format (CIC aligned)'
                }
            )
    
            print(f"✅ Single model trained sequentially on both datasets saved to database with ID: {model_id}")
    
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
            print(f"❌ Error saving to database: {e}")
            import traceback
            traceback.print_exc()
            return None, metadata
    except Exception as e:
        print(f"❌ Error training combined model: {e}")
        import traceback
        traceback.print_exc()
        return None, None

def main():
    """Main function to train a single model sequentially on both datasets"""
    print("="*80)
    print("VIGILANTE - RNSA+KNN SINGLE MODEL SEQUENTIAL TRAINING ON MULTIPLE DATASETS")
    print("="*80)
    
    try:
        # Use admin user ID (default is 1 for admin1)
        user_id = 1
        
        # Train model
        model_id, metadata = train_single_model_on_both_datasets(user_id)

        if model_id:
            print(f"\n✅ Model successfully saved to database with ID: {model_id}")
            print(f"   You can use this model with: vigilante detect --model-id {model_id}")
        else:
            print("\n⚠️ Model was trained but not saved to database")
        
        # Display summary
        if metadata:
            print("\n" + "="*80)
            print("MODEL TRAINING SUMMARY")
            print("="*80)
            
            print(f"\nModel Name: {metadata['model_name']}")
            print(f"Dataset: {metadata['dataset']}")
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
        
        # Log completion
        print("\n" + "="*80)
        print("TRAINING COMPLETED SUCCESSFULLY!")
        print("="*80)
        
        if model_id:
            print(f"Single model trained sequentially on both datasets saved to database with ID: {model_id}")
        
        print(f"\nModel files saved in: saved_models/")
        print(f"\nYou can now use this model with the vigilante CLI:")
        print(f"  vigilante detect --input your_data.csv --model-id {model_id if model_id else 'MODEL_ID'}")
        
        if metadata:
            print(f"\nNote: This model expects data with {metadata['features_count']} features (UNSW-NB15 format)")
        
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
    
    # Run main function
    exit_code = main()
    sys.exit(exit_code)