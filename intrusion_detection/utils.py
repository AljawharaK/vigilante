"""Utility functions for the intrusion detection system"""

import os
import json
import yaml
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional
import pandas as pd

def get_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def save_results(results: Dict[str, Any], output_path: str, format: str = 'json'):
    """Save results to file in specified format"""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    if format.lower() == 'json':
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
    elif format.lower() == 'yaml':
        with open(output_path, 'w') as f:
            yaml.dump(results, f, default_flow_style=False)
    elif format.lower() == 'csv':
        # Convert results to DataFrame if possible
        if 'predictions' in results:
            df = pd.DataFrame(results['predictions'])
            df.to_csv(output_path, index=False)
        else:
            raise ValueError("Results cannot be converted to CSV")
    else:
        raise ValueError(f"Unsupported format: {format}")
    
    print(f"Results saved to: {output_path}")

def validate_data_file(file_path: str, required_columns: Optional[list] = None) -> bool:
    """Validate data file structure"""
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        return False
    
    try:
        # Try to read the file
        df = pd.read_csv(file_path, nrows=1)  # Only read first row to check columns
        
        if required_columns:
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                print(f"Error: Missing required columns: {missing_columns}")
                return False
        
        return True
    
    except Exception as e:
        print(f"Error reading file: {e}")
        return False

def create_model_directory(model_name: str, base_dir: str = "models") -> str:
    """Create directory structure for a model"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_dir = os.path.join(base_dir, f"{model_name}_{timestamp}")
    
    os.makedirs(model_dir, exist_ok=True)
    os.makedirs(os.path.join(model_dir, "checkpoints"), exist_ok=True)
    os.makedirs(os.path.join(model_dir, "logs"), exist_ok=True)
    os.makedirs(os.path.join(model_dir, "results"), exist_ok=True)
    
    return model_dir

def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML or JSON file"""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    with open(config_path, 'r') as f:
        if config_path.endswith('.yaml') or config_path.endswith('.yml'):
            return yaml.safe_load(f)
        elif config_path.endswith('.json'):
            return json.load(f)
        else:
            raise ValueError("Config file must be YAML or JSON")

def format_bytes(size: float) -> str:
    """Format bytes to human readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

def get_system_info() -> Dict[str, Any]:
    """Get system information"""
    import platform
    import psutil
    
    info = {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "processor": platform.processor(),
        "cpu_count": psutil.cpu_count(),
        "total_memory": format_bytes(psutil.virtual_memory().total),
        "available_memory": format_bytes(psutil.virtual_memory().available),
    }
    
    # Try to get GPU info if available
    try:
        import torch
        if torch.cuda.is_available():
            info["gpu"] = torch.cuda.get_device_name(0)
            info["gpu_memory"] = format_bytes(torch.cuda.get_device_properties(0).total_memory)
    except ImportError:
        pass
    
    return info