#!/usr/bin/env python3
"""
Vigilante Intrusion Detection System
Main entry point for both CLI and GUI modes
"""

import sys
import os
import argparse
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    """Main entry point - decides whether to run CLI or GUI"""
    
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