# intrusion_detection/main.py

#!/usr/bin/env python3
"""
Vigilante Intrusion Detection System
Main entry point for both CLI and GUI modes
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    """Main entry point - decides whether to run CLI or GUI"""
    
    # Validate environment before anything else
    try:
        from .config import validate_environment
        validate_environment()
    except ImportError:
        # config.py might not exist yet, handle gracefully
        from dotenv import load_dotenv
        load_dotenv()
        
        required_vars = ['DATABASE_URL', 'RESEND_API_KEY']
        missing = [v for v in required_vars if not os.getenv(v)]
        if missing:
            print(f"❌ Missing required environment variables: {', '.join(missing)}")
            print("Please create a .env file with these variables")
            sys.exit(1)
    
    # Check if GUI mode is requested
    if len(sys.argv) > 1 and sys.argv[1] == "interactive-gui":
        # Launch GUI
        try:
            from .gui import main as gui_main
            gui_main()
        except ImportError as e:
            print(f"Error: Could not launch GUI - {e}")
            print("Make sure flet is installed: pip install flet")
            sys.exit(1)
    else:
        # Run normal CLI
        from .cli import main as cli_main
        cli_main()

if __name__ == "__main__":
    main()