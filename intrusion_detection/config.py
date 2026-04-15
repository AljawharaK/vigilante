# intrusion_detection/config.py

import os
from dotenv import load_dotenv
from typing import Dict, List

load_dotenv()

class ConfigValidator:
    """Validate required environment variables"""
    
    REQUIRED_VARS = {
        'DATABASE_URL': 'PostgreSQL connection string',
        'RESEND_API_KEY': 'Resend email API key',
    }
    
    OPTIONAL_VARS = {
        'RESEND_FROM_EMAIL': 'noreply@updates.vigilanteapps.com',
        'APP_NAME': 'Vigilante',
        'APP_ENV': 'production',
        'SESSION_EXPIRY_HOURS': '24',
        'OTP_EXPIRY_MINUTES': '10',
        'LOG_LEVEL': 'INFO',
        'LOG_FILE': 'vigilante.log',
        'ADMIN_EMAIL': 'admin@vigilante.com',
        'ADMIN_PASSWORD_HASH': None,  # Will be generated if not set
    }
    
    @classmethod
    def validate(cls) -> Dict[str, bool]:
        """Validate all required environment variables are set"""
        results = {}
        missing_vars = []
        
        for var, description in cls.REQUIRED_VARS.items():
            value = os.getenv(var)
            if value:
                results[var] = True
            else:
                results[var] = False
                missing_vars.append(f"  • {var} - {description}")
        
        if missing_vars:
            print("❌ Missing required environment variables:")
            for var in missing_vars:
                print(var)
            print("\nPlease create a .env file with these variables (see .env.example)")
            return results
        
        print("✅ All required environment variables are set")
        return results
    
    @classmethod
    def get_config(cls) -> Dict[str, str]:
        """Get all configuration values with defaults for optional vars"""
        config = {}
        
        # Get required vars (must exist)
        for var in cls.REQUIRED_VARS:
            config[var] = os.getenv(var)
            if not config[var]:
                raise ValueError(f"Required config {var} not found")
        
        # Get optional vars with defaults
        for var, default in cls.OPTIONAL_VARS.items():
            config[var] = os.getenv(var, default)
        
        return config

def validate_environment():
    """Quick validation function to call at startup"""
    return ConfigValidator.validate()