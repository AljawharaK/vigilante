#!/usr/bin/env python3
"""Main CLI interface for Vigilante Intrusion Detection System"""

import argparse
import sys
import os
import json
import tempfile
from datetime import datetime, timedelta
from getpass import getpass
from typing import Optional, Tuple, Union, Dict
import traceback
from pathlib import Path
from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.syntax import Syntax
from rich.box import ROUNDED
import pandas as pd
import numpy as np
from .database import DatabaseManager
from .auth import AuthManager
from .model_trainer import ModelTrainer
from .model import IntrusionDetectionModel
from .utils import generate_pdf_report, format_table, get_system_info, json_serializable

console = Console()

class VigilanteCLI:
    """Main CLI class for Vigilante IDS"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.auth = AuthManager(self.db)
        self.trainer = ModelTrainer()
        self.current_model = None
        self.session_file = Path.home() / ".vigilante_session"
        
        self.setup_argparse()
        self.load_session()
    
    def setup_argparse(self):
        """Setup argument parser with comprehensive commands"""
        parser = argparse.ArgumentParser(
            description='Vigilante - Intrusion Detection System CLI',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  vigilante login                                      # Interactive login
  vigilante train --input training_data.csv 
  --model-name "Network Traffic Model" 
  --features "Flow Duration,Fwd Packets,Bwd Packets"    # Train model
  vigilante detect --input new_traffic.csv 
  --model-id 1 --threshold 0.6 --output results.json   # Detect anomalies
  vigilante admin user-create --username analyst1 --email analyst@company.com --role Analyst  # Create user (admin only)
  vigilante summary --period 7d                        # Weekly summary
  vigilante explain --detection-id 1                   # Explain detection
            """
        )
        
        # Main command groups
        subparsers = parser.add_subparsers(dest='command', help='Command')
        
        # Authentication commands
        auth_parser = subparsers.add_parser('login', help='Login to system')
        auth_parser.add_argument('--username', help='Username')
        auth_parser.add_argument('--password', help='Password (not recommended)')
        
        subparsers.add_parser('logout', help='Logout from system')
        uninstall_parser = subparsers.add_parser('uninstall', help='Completely remove Vigilante from system')
        uninstall_parser.add_argument('--force', action='store_true', help='Force uninstall without confirmation')
        
        reset_parser = subparsers.add_parser('reset-pass', help='Reset password')
        reset_parser.add_argument('--username', help='Username')
        
        # User Management (Admin only)
        admin_parser = subparsers.add_parser('admin', help='Administrator commands')
        admin_sub = admin_parser.add_subparsers(dest='admin_command')
        
        # User management (simplified roles)
        user_create = admin_sub.add_parser('user-create', help='Create new user')
        user_create.add_argument('--username', required=True, help='Username')
        user_create.add_argument('--email', required=True, help='Email')
        user_create.add_argument('--role', choices=['Administrator', 'Analyst'], 
                                default='Analyst', help='User role')
        
        user_modify = admin_sub.add_parser('user-modify', help='Modify user')
        user_modify.add_argument('--username', required=True, help='Username')
        user_modify.add_argument('--role', choices=['Administrator', 'Analyst'], 
                                help='New role')
        
        user_deactivate = admin_sub.add_parser('user-deactivate', help='Deactivate user')
        user_deactivate.add_argument('--username', required=True, help='Username')
        
        # System reports (Admin only)
        system_report = admin_sub.add_parser('system-report', help='Generate system report')
        system_report.add_argument('--period', default='7d', help='Period (e.g., 7d, 30d)')
        system_report.add_argument('--output', help='Output file (PDF)')
        
        audit_logs = admin_sub.add_parser('audit-logs', help='View audit logs')
        audit_logs.add_argument('--period', default='30d', help='Period')
        audit_logs.add_argument('--output', help='Output file (CSV)')
        
        # Detection commands (available to both Admin and Analyst)
        detect_parser = subparsers.add_parser('detect', help='Detect anomalies')
        detect_parser.add_argument('--input', required=True, help='Input CSV file')
        detect_parser.add_argument('--model-id', type=int, help='Model ID from database')
        detect_parser.add_argument('--model-path', help='Path to model file')
        detect_parser.add_argument('--threshold', type=float, help='Override model threshold (0.0-1.0)')
        detect_parser.add_argument('--output', help='Output JSON file')
        
        # Training commands (available to both Admin and Analyst)
        train_parser = subparsers.add_parser('train', help='Train model')
        train_parser.add_argument('--input', required=True, help='Training data CSV')
        train_parser.add_argument('--features', help='Comma-separated features')
        train_parser.add_argument('--model-name', help='Model name')
        train_parser.add_argument('--output', help='Output model path')
        
        # Analysis commands (available to both Admin and Analyst)
        summary_parser = subparsers.add_parser('summary', help='Get detection summary')
        summary_parser.add_argument('--period', default='7d', help='Period')
        summary_parser.add_argument('--output', help='Output JSON file')
        
        explain_parser = subparsers.add_parser('explain', help='Explain detection results')
        explain_parser.add_argument('--detection-id', type=int, help='Detection ID')
        explain_parser.add_argument('--input', help='Detection results JSON')
        
        # Model management
        subparsers.add_parser('list-models', help='List available models')
        
        # System info
        subparsers.add_parser('status', help='Show system status')
        
        # GUI command
        gui_parser = subparsers.add_parser('interactive-gui', help='Launch interactive GUI mode')
        gui_parser.add_argument('--port', type=int, default=8550, help='Port for GUI server')
        gui_parser.add_argument('--web', action='store_true', help='Run as web app (opens in browser)')

        # Version flag (outside subparsers)
        parser.add_argument('--version', action='store_true', help='Show version information')
        parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
        
        self.parser = parser
    
    def load_session(self):
        """Load encrypted session from file with security checks"""
        from .utils import SecureSessionManager
        
        try:
            session_data = SecureSessionManager.load_session_secure()
            
            if session_data:
                session_token = session_data.get('session_token')
                if session_token and self.auth.validate_session(session_token):
                    console.print(f"[green]✓ Secure session loaded for {self.auth.current_user['username']}[/green]")
                    return True
                else:
                    # Session token invalid, clear it
                    SecureSessionManager.clear_session_secure()
                    console.print("[yellow]⚠️ Invalid session, please login again[/yellow]")
            return False
            
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load session: {e}[/yellow]")
            return False

    def save_session(self):
        """Save encrypted session to file with integrity protection"""
        from .utils import SecureSessionManager
        
        if self.auth.current_session and self.auth.current_user:
            success = SecureSessionManager.save_session_secure(
                self.auth.current_session,
                self.auth.current_user['username']
            )
            
            if success:
                console.print("[dim]✓ Session saved securely[/dim]")
            else:
                console.print("[yellow]⚠️ Could not save session securely[/yellow]")

    def clear_session(self):
        """Securely clear session file"""
        from .utils import SecureSessionManager
        
        SecureSessionManager.clear_session_secure()
        console.print("[dim]✓ Session cleared[/dim]")
    
    def check_auth(self):
        """Check if user is authenticated"""
        if not self.auth.is_authenticated():
            console.print("[red]Error: Authentication required[/red]")
            console.print("Use: [cyan]vigilante login[/cyan]")
            return False
        return True
    
    def check_permission(self, permission: str):
        """Check if user has specific permission"""
        if not self.check_auth():
            return False
        
        if not self.auth.has_permission(permission):
            console.print(f"[red]Error: Permission denied[/red]")
            
            if self.auth.is_analyst():
                console.print("[yellow]Analyst role restrictions:[/yellow]")
                console.print("  ✓ Can train models")
                console.print("  ✓ Can run detection")
                console.print("  ✓ Can view summaries")
                console.print("  ✓ Can generate explanations")
                console.print("  ✗ Cannot manage users")
                console.print("  ✗ Cannot view audit logs")
                console.print("  ✗ Cannot generate system reports")
            
            return False
        
        return True
    
    def check_admin(self):
        """Check if user is Administrator"""
        if not self.check_auth():
            return False
        
        if not self.auth.is_admin():
            console.print("[red]Error: Administrator privileges required[/red]")
            console.print("[yellow]This command is only available to Administrators[/yellow]")
            return False
        
        return True
    
    def validate_input_file_secure(self, file_path: str, expected_type: str = 'csv') -> Tuple[bool, str, Optional[Union[pd.DataFrame, Dict]]]:
        """
        Validate input file with security checks before processing
        
        Args:
            file_path: Path to input file
            expected_type: Expected file type ('csv' or 'json')
            
        Returns:
            Tuple of (is_valid, message, data_frame_or_json)
        """
        from .utils import SecurityValidator
        
        # First, validate file existence and basic properties
        is_valid, error = SecurityValidator.validate_file_input(file_path)
        if not is_valid:
            return False, error, None
        
        # Validate content based on type
        if expected_type == 'csv' or file_path.endswith('.csv'):
            is_valid, error, df_preview = SecurityValidator.validate_csv_content(file_path)
            if not is_valid:
                return False, error, None
            
            return True, "OK", df_preview
        
        elif expected_type == 'json' or file_path.endswith('.json'):
            is_valid, error, json_data = SecurityValidator.validate_json_content(file_path)
            if not is_valid:
                return False, error, None
            
            console.print(f"[green]✓ Security validation passed for {file_path}[/green]")
            return True, "OK", json_data
        
        else:
            return False, f"Unsupported file type: {expected_type}", None


    def check_rate_limit(self, action: str) -> Tuple[bool, int]:
        """
        Check rate limit for user actions to prevent DoS
        
        Args:
            action: Action being performed
            
        Returns:
            Tuple of (is_allowed, remaining_requests)
        """
        from .utils import SecurityValidator
        
        # Rate limiting settings per action
        rate_limits = {
            'detect': {'max': 70, 'window': 3600},   # 70 detections per hour
            'train': {'max': 70, 'window': 3600},    # 70 trainings per hour
            'login': {'max': 40, 'window': 3600},      # 40 login attempts per 5 minutes
        }
        
        if action not in rate_limits:
            return True, 100  # No limit for other actions
        
        limits = rate_limits[action]
        user_id = self.auth.current_user['id'] if self.auth.current_user else 0
        
        # Check with database (simplified - implement full rate limiting)
        # For now, return allowed
        return True, limits['max']


    def secure_file_cleanup(self, file_path: str):
        """
        Securely cleanup temporary files after processing
        
        Args:
            file_path: Path to file to cleanup
        """
        import tempfile
        import shutil
        
        try:
            if os.path.exists(file_path):
                # Securely overwrite before deletion for sensitive files
                if file_path.endswith(('.csv', '.json')):
                    with open(file_path, 'wb') as f:
                        f.write(os.urandom(os.path.getsize(file_path)))
                
                os.remove(file_path)
                console.print(f"[dim]✓ Cleaned up temporary file: {file_path}[/dim]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not cleanup {file_path}: {e}[/yellow]")

    def handle_interactive_gui(self, args):
        """Launch the interactive GUI mode"""
        console.print("[cyan]Starting Vigilante Interactive GUI...[/cyan]")
    
        try:
            # Import flet
            import flet as ft
        
            # Import the GUI module
            from .gui import main as gui_main
        
            # Set environment variables for flet
            os.environ['FLET_SERVER_PORT'] = str(args.port)
        
            # Pass session token to GUI if authenticated
            if self.auth.is_authenticated():
                os.environ['VIGILANTE_SESSION_TOKEN'] = self.auth.current_session
        
            if args.web:
                os.environ['FLET_WEB'] = 'true'
                console.print(f"[green]✓ GUI will open in your browser at http://localhost:{args.port}[/green]")
            else:
                console.print(f"[green]✓ GUI window opening on port {args.port}...[/green]")
        
            # Run the GUI
            ft.app(target=gui_main)
        
        except ImportError as e:
            console.print(f"[red]Error: Could not launch GUI - {e}[/red]")
            console.print("[yellow]Make sure flet is installed: pip install flet[/yellow]")
        except Exception as e:
            console.print(f"[red]Error launching GUI: {e}[/red]")

    def handle_login(self, args):
        """Handle login with OTP verification"""
        # Get username
        if not args.username:
            args.username = input("Username: ").strip()
        
        # Get password securely
        if args.password:
            password = args.password
        else:
            password = getpass("Password: ")
        
        # Step 1: Verify credentials
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description="Verifying credentials...", total=None)
            result = self.auth.login(args.username, password)
        
        if not result['success']:
            console.print(f"[red]✗ {result['message']}[/red]")
            return
        
        # Check if password needs to be changed
        if result.get('requires_password_change'):
            console.print("[yellow]You must change your password before logging in.[/yellow]")
            self.handle_password_change_interactive(result['user_id'])
            return
        
        # Step 2: OTP verification
        if result.get('requires_otp'):
            console.print(f"[green]✓ Credentials verified[/green]")
            console.print(f"[cyan]OTP sent to {result['email']}[/cyan]")
            
            otp_code = input("Enter OTP Code: ").strip()
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                progress.add_task(description="Verifying OTP...", total=None)
                otp_result = self.auth.verify_otp(otp_code)
            
            if not otp_result['success']:
                console.print(f"[red]✗ {otp_result['message']}[/red]")
                return
            
            result = otp_result
        
        # Login successful
        console.print(f"[green]✓ Login successful! Welcome {result['username']}[/green]")
        console.print(f"Role: [cyan]{result.get('role', 'Analyst')}[/cyan]")
        
        # Save session
        self.save_session()
    
    def handle_logout(self, args):
        """Handle logout"""
        if self.auth.is_authenticated():
            self.auth.logout()
            self.clear_session()
            console.print("[green]✓ Logged out successfully[/green]")
        else:
            console.print("[yellow]Not logged in[/yellow]")
    
    def handle_uninstall(self, args):
        """Completely remove Vigilante from the system"""
        console.print("[bold red]VIGILANTE UNINSTALLATION[/bold red]")
        console.print("[yellow]This will permanently remove:[/yellow]")
        console.print("  • Vigilante executable from ~/.local/bin/vigilante.exe")
        console.print("  • Pipx/venv installations")
        console.print("  • Session files")
        console.print("  • Saved models")
        console.print("  • Configuration files")
        console.print("  • All user data from the system\n")
        
        # Force confirmation
        console.print("[bold red]⚠️  WARNING: This action is IRREVERSIBLE! ⚠️[/bold red]")
        confirm = input("Type 'DELETE VIGILANTE' to confirm uninstallation: ").strip()
        
        if confirm != "DELETE VIGILANTE":
            console.print("[green]Uninstallation cancelled.[/green]")
            return
        
        console.print("\n[cyan]Starting uninstallation...[/cyan]")
        
        results = {
            "success": [],
            "failed": [],
            "skipped": []
        }
        
        # 1. Clear session and logout
        console.print("[cyan]→ Clearing active session...[/cyan]")
        try:
            if self.auth.is_authenticated():
                self.auth.logout()
            self.clear_session()
            results["success"].append("Cleared session")
            console.print("[green]  ✓ Session cleared[/green]")
        except Exception as e:
            results["failed"].append(f"Session clear: {e}")
            console.print(f"[red]  ✗ Failed to clear session: {e}[/red]")
        
        # 2. Remove session file
        console.print("[cyan]→ Removing session file...[/cyan]")
        try:
            session_file = Path.home() / ".vigilante_session"
            if session_file.exists():
                session_file.unlink()
                results["success"].append("Removed session file")
                console.print("[green]  ✓ Session file removed[/green]")
            else:
                results["skipped"].append("Session file not found")
                console.print("[yellow]  ! Session file not found[/yellow]")
        except Exception as e:
            results["failed"].append(f"Session file: {e}")
            console.print(f"[red]  ✗ Failed to remove session file: {e}[/red]")
        
        # 3. Remove ~/.local/bin/vigilante.exe
        console.print("[cyan]→ Removing vigilante executable...[/cyan]")
        local_bin = Path.home() / ".local" / "bin" / "vigilante.exe"
        try:
            if local_bin.exists():
                local_bin.unlink()
                results["success"].append("Removed ~/.local/bin/vigilante.exe")
                console.print("[green]  ✓ ~/.local/bin/vigilante.exe removed[/green]")
            else:
                # Also check for non-.exe version
                local_bin_no_exe = Path.home() / ".local" / "bin" / "vigilante"
                if local_bin_no_exe.exists():
                    local_bin_no_exe.unlink()
                    results["success"].append("Removed ~/.local/bin/vigilante")
                    console.print("[green]  ✓ ~/.local/bin/vigilante removed[/green]")
                else:
                    results["skipped"].append("Executable not found in ~/.local/bin")
                    console.print("[yellow]  ! Executable not found in ~/.local/bin[/yellow]")
        except Exception as e:
            results["failed"].append(f"Executable removal: {e}")
            console.print(f"[red]  ✗ Failed to remove executable: {e}[/red]")
        
        # 4. Remove pipx installation
        console.print("[cyan]→ Removing pipx installation...[/cyan]")
        try:
            import subprocess
            # Check if installed via pipx
            result = subprocess.run(["pipx", "list"], capture_output=True, text=True)
            if "vigilante" in result.stdout:
                subprocess.run(["pipx", "uninstall", "vigilante"], capture_output=True, text=True)
                results["success"].append("Uninstalled via pipx")
                console.print("[green]  ✓ Pipx uninstallation completed[/green]")
            else:
                results["skipped"].append("Not installed via pipx")
                console.print("[yellow]  ! Not installed via pipx[/yellow]")
        except FileNotFoundError:
            results["skipped"].append("pipx not installed")
            console.print("[yellow]  ! pipx not found on system[/yellow]")
        except Exception as e:
            results["failed"].append(f"Pipx uninstall: {e}")
            console.print(f"[red]  ✗ Pipx uninstall failed: {e}[/red]")
        
        # 5. Remove venv if exists in current directory
        console.print("[cyan]→ Removing virtual environment...[/cyan]")
        venv_path = Path.cwd() / ".venv"
        try:
            if venv_path.exists() and venv_path.is_dir():
                import shutil
                shutil.rmtree(venv_path)
                results["success"].append("Removed .venv directory")
                console.print("[green]  ✓ Virtual environment removed[/green]")
            else:
                # Check parent directory
                parent_venv = Path.cwd().parent / ".venv"
                if parent_venv.exists() and parent_venv.is_dir():
                    shutil.rmtree(parent_venv)
                    results["success"].append("Removed parent .venv directory")
                    console.print("[green]  ✓ Parent virtual environment removed[/green]")
                else:
                    results["skipped"].append(".venv not found")
                    console.print("[yellow]  ! Virtual environment not found[/yellow]")
        except Exception as e:
            results["failed"].append(f"Venv removal: {e}")
            console.print(f"[red]  ✗ Failed to remove virtual environment: {e}[/red]")
        
        # 6. Remove saved_models directory
        console.print("[cyan]→ Removing saved models...[/cyan]")
        models_dir = Path.cwd() / "saved_models"
        try:
            if models_dir.exists() and models_dir.is_dir():
                import shutil
                shutil.rmtree(models_dir)
                results["success"].append("Removed saved_models directory")
                console.print("[green]  ✓ Saved models removed[/green]")
            else:
                results["skipped"].append("saved_models directory not found")
                console.print("[yellow]  ! saved_models directory not found[/yellow]")
        except Exception as e:
            results["failed"].append(f"Models removal: {e}")
            console.print(f"[red]  ✗ Failed to remove saved models: {e}[/red]")
        
        # 7. Remove .env file
        console.print("[cyan]→ Removing environment configuration...[/cyan]")
        env_file = Path.cwd() / ".env"
        try:
            if env_file.exists():
                env_file.unlink()
                results["success"].append("Removed .env file")
                console.print("[green]  ✓ .env file removed[/green]")
            else:
                results["skipped"].append(".env file not found")
                console.print("[yellow]  ! .env file not found[/yellow]")
        except Exception as e:
            results["failed"].append(f".env removal: {e}")
            console.print(f"[red]  ✗ Failed to remove .env file: {e}[/red]")
        
        # 8. Remove detections directory (if exists)
        console.print("[cyan]→ Removing detection history...[/cyan]")
        detections_dir = Path.cwd() / "detections"
        try:
            if detections_dir.exists() and detections_dir.is_dir():
                import shutil
                shutil.rmtree(detections_dir)
                results["success"].append("Removed detections directory")
                console.print("[green]  ✓ Detection history removed[/green]")
            else:
                results["skipped"].append("detections directory not found")
                console.print("[yellow]  ! detections directory not found[/yellow]")
        except Exception as e:
            results["failed"].append(f"Detections removal: {e}")
            console.print(f"[red]  ✗ Failed to remove detections: {e}[/red]")
        
        # 9. Remove evaluations directory (if exists)
        console.print("[cyan]→ Removing evaluation history...[/cyan]")
        evaluations_dir = Path.cwd() / "evaluations"
        try:
            if evaluations_dir.exists() and evaluations_dir.is_dir():
                import shutil
                shutil.rmtree(evaluations_dir)
                results["success"].append("Removed evaluations directory")
                console.print("[green]  ✓ Evaluation history removed[/green]")
            else:
                results["skipped"].append("evaluations directory not found")
                console.print("[yellow]  ! evaluations directory not found[/yellow]")
        except Exception as e:
            results["failed"].append(f"Evaluations removal: {e}")
            console.print(f"[red]  ✗ Failed to remove evaluations: {e}[/red]")
        
        # 10. Uninstall Python package
        console.print("[cyan]→ Uninstalling Python package...[/cyan]")
        try:
            import subprocess
            result = subprocess.run(["pip", "uninstall", "vigilante", "-y"], 
                                capture_output=True, text=True)
            if result.returncode == 0:
                results["success"].append("Uninstalled Python package")
                console.print("[green]  ✓ Python package uninstalled[/green]")
            else:
                # Try pip3
                result = subprocess.run(["pip3", "uninstall", "vigilante", "-y"], 
                                    capture_output=True, text=True)
                if result.returncode == 0:
                    results["success"].append("Uninstalled Python package (pip3)")
                    console.print("[green]  ✓ Python package uninstalled (pip3)[/green]")
                else:
                    results["skipped"].append("Package not found in pip")
                    console.print("[yellow]  ! Package not found in pip[/yellow]")
        except Exception as e:
            results["failed"].append(f"Pip uninstall: {e}")
            console.print(f"[red]  ✗ Pip uninstall failed: {e}[/red]")
        
        # 11. Remove .vigilante directory in home (if exists)
        console.print("[cyan]→ Removing user configuration...[/cyan]")
        vigilante_config = Path.home() / ".vigilante"
        try:
            if vigilante_config.exists():
                if vigilante_config.is_dir():
                    import shutil
                    shutil.rmtree(vigilante_config)
                else:
                    vigilante_config.unlink()
                results["success"].append("Removed ~/.vigilante")
                console.print("[green]  ✓ ~/.vigilante removed[/green]")
            else:
                results["skipped"].append("~/.vigilante not found")
                console.print("[yellow]  ! ~/.vigilante not found[/yellow]")
        except Exception as e:
            results["failed"].append(f"Config removal: {e}")
            console.print(f"[red]  ✗ Failed to remove ~/.vigilante: {e}[/red]")
        
        # 12. Optional: Database cleanup warning
        console.print("\n[bold yellow]Database Notice:[/bold yellow]")
        console.print("Your Vigilante data in the PostgreSQL database (Neon) has NOT been deleted.")
        console.print("This includes user accounts, models, detection history, and audit logs.")
        console.print("\nTo remove database data:")
        console.print("  1. Log into your Neon PostgreSQL console")
        console.print("  2. Drop the vigilante tables manually if desired")
        console.print("  3. Or contact your database administrator")
        
        # 13. Optional: Remove logs
        console.print("\n[cyan]→ Removing log files...[/cyan]")
        log_file = Path.cwd() / "viglante.log"
        try:
            if log_file.exists():
                log_file.unlink()
                results["success"].append("Removed viglante.log")
                console.print("[green]  ✓ Log file removed[/green]")
            else:
                results["skipped"].append("Log file not found")
                console.print("[yellow]  ! Log file not found[/yellow]")
        except Exception as e:
            results["failed"].append(f"Log removal: {e}")
            console.print(f"[red]  ✗ Failed to remove log: {e}[/red]")
        
        # Print summary
        console.print("\n" + "="*60)
        console.print("[bold]UNINSTALLATION SUMMARY[/bold]")
        console.print("="*60)
        
        console.print(f"\n[green]✓ Successfully removed ({len(results['success'])} items):[/green]")
        for item in results["success"]:
            console.print(f"  • {item}")
        
        if results["skipped"]:
            console.print(f"\n[yellow]! Skipped ({len(results['skipped'])} items):[/yellow]")
            for item in results["skipped"]:
                console.print(f"  • {item}")
        
        if results["failed"]:
            console.print(f"\n[red]✗ Failed ({len(results['failed'])} items):[/red]")
            for item in results["failed"]:
                console.print(f"  • {item}")
        
        console.print("\n[bold green]Vigilante has been mostly removed from your system.[/bold green]")
        console.print("[yellow]Note: Database data remains on Neon PostgreSQL server.[/yellow]")
        console.print("To completely remove, you may need to delete the vigilante directory manually.")
        
    def handle_reset_password(self, args):
        """Handle password reset"""
        username = args.username or input("Username: ").strip()
        
        user = self.db.get_user(username)
        if not user:
            console.print("[red]User not found[/red]")
            return
        
        # Get current password
        current_password = getpass("Current password: ")
        
        # Verify current password
        if not self.auth.verify_password(current_password, user['password_hash']):
            console.print("[red]Current password is incorrect[/red]")
            return
        
        # Get new password
        while True:
            new_password = getpass("New password: ")
            confirm_password = getpass("Confirm new password: ")
            
            if new_password != confirm_password:
                console.print("[red]Passwords do not match[/red]")
                continue
            
            if len(new_password) < 8:
                console.print("[red]Password must be at least 8 characters[/red]")
                continue
            
            break
        
        # Change password
        result = self.auth.change_password(user['id'], current_password, new_password)
        
        if result['success']:
            console.print("[green]✓ Password changed successfully[/green]")
        else:
            console.print(f"[red]✗ {result['message']}[/red]")
    
    # Admin Commands
    # intrusion_detection/cli.py

    def handle_admin_user_create(self, args):
        """Create new user (Administrator only)"""
        if not self.check_admin():
            return
        
        # Get password choice from admin
        console.print("\n[bold cyan]Create New User - Password Options:[/bold cyan]")
        console.print("1. Auto-generate random password (user must change on first login)")
        console.print("2. Set password manually now")
        console.print("3. User will set password on first login (no temporary password)")
        
        choice = input("\nSelect option (1-3): ").strip()
        
        temp_password = None
        password_hash = None
        
        if choice == "1":
            # Auto-generate random password
            import secrets
            import string
            # Generate a strong random password
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            temp_password = ''.join(secrets.choice(alphabet) for _ in range(12))
            password_hash = self.auth.hash_password(temp_password)
            must_change = True
            console.print(f"[yellow]Generated password: {temp_password}[/yellow]")
            
        elif choice == "2":
            # Admin sets password manually
            console.print("\n[cyan]Enter password for new user:[/cyan]")
            while True:
                password = getpass("Password: ")
                confirm = getpass("Confirm password: ")
                
                if password != confirm:
                    console.print("[red]Passwords do not match. Please try again.[/red]")
                    continue
                
                if len(password) < 8:
                    console.print("[red]Password must be at least 8 characters.[/red]")
                    continue
                
                # Optional: Add password strength check
                if not self.is_password_strong(password):
                    console.print("[yellow]Warning: Password is weak.[/yellow]")
                    proceed = input("Create user anyway? (y/n): ").strip().lower()
                    if proceed != 'y':
                        continue
                
                temp_password = password
                password_hash = self.auth.hash_password(password)
                must_change = False  # Admin set password, so user doesn't need to change
                break
                
        elif choice == "3":
            # No password - user must set on first login
            # Create a placeholder that forces password change
            placeholder = "force_change_on_login"
            password_hash = self.auth.hash_password(placeholder)
            must_change = True
            console.print("[green]User will set password on first login[/green]")
            
        else:
            console.print("[red]Invalid option. User creation cancelled.[/red]")
            return
        
        try:
            # Create user with simplified role
            user_id = self.db.create_user(
                username=args.username,
                password_hash=password_hash,
                email=args.email,
                role=args.role,
                created_by=self.auth.current_user['id'],
                must_change_password=must_change 
            )
            
            # Log audit event
            self.db.log_audit_event(
                user_id=self.auth.current_user['id'],
                username=self.auth.current_user['username'],
                action="user_create",
                resource=args.username,
                status="success",
                details={
                    "role": args.role, 
                    "email": args.email,
                    "password_set_by": "admin" if choice == "2" else "auto" if choice == "1" else "user"
                }
            )
            
            console.print(f"\n[green]✓ User '{args.username}' created successfully[/green]")
            console.print(f"Role: [cyan]{args.role}[/cyan]")
            console.print(f"Email: [cyan]{args.email}[/cyan]")
            console.print(f"Status: [green]Active[/green]")
            
            if temp_password:
                console.print(f"\n[bold yellow]Password Information:[/bold yellow]")
                console.print(f"Password: [yellow]{temp_password}[/yellow]")
                if must_change:
                    console.print("[bold yellow]⚠️ User must change password on first login[/bold yellow]")
                else:
                    console.print("[green]✓ Password set by admin - user can use immediately[/green]")
            else:
                console.print("\n[green]✓ User will set password during first login[/green]")
            
        except Exception as e:
            console.print(f"[red]✗ Failed to create user: {e}[/red]")

    def is_password_strong(self, password: str) -> bool:
        """Check if password meets strength requirements"""
        import re
        
        checks = []
        
        # Length check
        if len(password) >= 12:
            checks.append("✓ Length (12+ chars)")
        elif len(password) >= 8:
            checks.append("⚠️ Length (8-11 chars)")
        else:
            checks.append("✗ Length (<8 chars)")
        
        # Uppercase check
        if re.search(r'[A-Z]', password):
            checks.append("✓ Uppercase letter")
        else:
            checks.append("✗ Missing uppercase")
        
        # Lowercase check
        if re.search(r'[a-z]', password):
            checks.append("✓ Lowercase letter")
        else:
            checks.append("✗ Missing lowercase")
        
        # Digit check
        if re.search(r'\d', password):
            checks.append("✓ Number")
        else:
            checks.append("✗ Missing number")
        
        # Special character check
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            checks.append("✓ Special character")
        else:
            checks.append("✗ Missing special character")
        
        # Calculate strength score
        score = sum([
            len(password) >= 8,
            bool(re.search(r'[A-Z]', password)),
            bool(re.search(r'[a-z]', password)),
            bool(re.search(r'\d', password)),
            bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        ])
        
        console.print("\n[cyan]Password Strength Check:[/cyan]")
        for check in checks:
            if check.startswith("✓"):
                console.print(f"  [green]{check}[/green]")
            elif check.startswith("⚠️"):
                console.print(f"  [yellow]{check}[/yellow]")
            else:
                console.print(f"  [red]{check}[/red]")
        
        if score >= 4:
            console.print("[green]✓ Password is strong[/green]")
            return True
        elif score >= 3:
            console.print("[yellow]⚠️ Password is moderate[/yellow]")
            return True  # Still allow, but warn
        else:
            console.print("[red]✗ Password is weak[/red]")
            return False
    
    def handle_admin_user_deactivate(self, args):
        """Deactivate user (Administrator only)"""
        if not self.check_admin():
            return
        
        # Confirm action
        console.print(f"[yellow]⚠️ You are about to deactivate user '{args.username}'[/yellow]")
        
        # Get user info
        user = self.db.get_user(args.username)
        if not user:
            console.print(f"[red]User '{args.username}' not found[/red]")
            return
        
        console.print(f"Role: [cyan]{user.get('role_name', 'Unknown')}[/cyan]")
        
        # Prevent deactivating the only admin
        if user.get('role_name') == 'Administrator':
            admin_count = self.db.count_admins()
            if admin_count <= 1:
                console.print("[red]Cannot deactivate the only Administrator[/red]")
                console.print("[yellow]System requires at least one active Administrator[/yellow]")
                return
        
        confirm = input("Confirm (y/n): ").strip().lower()
        
        if confirm != 'y':
            console.print("[yellow]Operation cancelled[/yellow]")
            return
        
        try:
            # Deactivate user
            self.db.deactivate_user(user['id'], self.auth.current_user['id'])
            
            # Invalidate all sessions
            self.db.invalidate_user_sessions(user['id'])
            
            # Log audit event
            self.db.log_audit_event(
                user_id=self.auth.current_user['id'],
                username=self.auth.current_user['username'],
                action="user_deactivate",
                resource=args.username,
                status="success"
            )
            
            console.print(f"[green]✓ User '{args.username}' deactivated[/green]")
            console.print("[yellow]All access rights revoked[/yellow]")
            
        except Exception as e:
            console.print(f"[red]✗ Failed to deactivate user: {e}[/red]")
    
    def handle_admin_user_modify(self, args):
        """Modify user (Administrator only)"""
        if not self.check_admin():
            return
        
        try:
            # Get user
            user = self.db.get_user(args.username)
            if not user:
                console.print(f"[red]User '{args.username}' not found[/red]")
                return
            
            if args.role:
                # Update role
                if args.role not in ['Administrator', 'Analyst']:
                    console.print(f"[red]Invalid role. Must be 'Administrator' or 'Analyst'[/red]")
                    return
                
                # Cannot demote the only admin
                if args.role == 'Analyst' and user['role_name'] == 'Administrator':
                    # Check if this is the only admin
                    admin_count = self.db.count_admins()
                    if admin_count <= 1:
                        console.print("[red]Cannot demote the only Administrator[/red]")
                        console.print("[yellow]System requires at least one Administrator[/yellow]")
                        return
                
                username = self.db.update_user_role(user['id'], args.role, self.auth.current_user['id'])
                
                # Log audit event
                self.db.log_audit_event(
                    user_id=self.auth.current_user['id'],
                    username=self.auth.current_user['username'],
                    action="user_role_update",
                    resource=args.username,
                    status="success",
                    details={"new_role": args.role}
                )
                
                console.print(f"[green]✓ Role for user '{username}' updated to '{args.role}'[/green]")
        
        except Exception as e:
            console.print(f"[red]✗ Failed to modify user: {e}[/red]")
    
    def handle_admin_audit_logs(self, args):
        """View audit logs (Administrator only)"""
        if not self.check_admin():
            return

        period_days = int(args.period.rstrip('d'))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description="Retrieving audit logs...", total=None)
            logs = self.db.get_audit_logs(period_days)

        if not logs:
            console.print("[yellow]No audit logs found for the specified period[/yellow]")
            return
        
        # Filter out None values
        logs = [log for log in logs if log is not None]

        # Display summary stats
        console.print(f"[green]Found {len(logs)} audit log entries[/green]\n")

        # Create detailed table with better formatting
        table = Table(title=f"Audit Logs - Last {args.period}", box=ROUNDED)
        table.add_column("ID", style="dim", width=6)
        table.add_column("Timestamp", style="cyan", width=20)
        table.add_column("User", style="green", width=15)
        table.add_column("Action", style="yellow", width=20)
        table.add_column("Resource", style="blue", width=30)
        table.add_column("Status", style="magenta", width=10)

        # Color-code different action types
        action_colors = {
            'login': 'green',
            'logout': 'yellow',
            'model_train': 'cyan',
            'detect': 'blue',
            'user_create': 'purple',
            'user_deactivate': 'red',
            'password_change': 'orange',
            'user_role_update': 'magenta'
        }

        for log in logs[:100]:  # Show first 100
            timestamp = log['created_at'].strftime('%Y-%m-%d %H:%M:%S') if hasattr(log['created_at'], 'strftime') else str(log.get('created_at', ''))[:19]
            username = log.get('username') or 'System'
            resource = log.get('resource') or '-'
            
            # Truncate long resource names
            if len(resource) > 25:
                resource = resource[:22] + '...'
            
            # Get action color
            action = log.get('action', '')
            
            table.add_row(
                str(log.get('id', '')),
                timestamp,
                username,
                f"[{action_colors.get(action, 'yellow')}]{action}[/{action_colors.get(action, 'yellow')}]",
                resource,
                log.get('status', 'success')
            )

        console.print(table)
        console.print(f"[dim]Showing {min(100, len(logs))} of {len(logs)} logs[/dim]")

        # Show action summary
        from collections import Counter
        actions = Counter([log.get('action', '') for log in logs])

        summary_table = Table(title="Action Summary", box=ROUNDED)
        summary_table.add_column("Action", style="cyan")
        summary_table.add_column("Count", style="green", justify="right")

        for action, count in actions.most_common(10):
            summary_table.add_row(action, str(count))

        console.print(summary_table)

        # Save to CSV if requested
        if args.output:
            try:
                df = pd.DataFrame(logs)
                df.to_csv(args.output, index=False)
                console.print(f"[green]✓ Full log saved to: {args.output}[/green]")
            except Exception as e:
                console.print(f"[red]Failed to save CSV: {e}[/red]")

    def handle_admin_system_report(self, args):
        """Generate system report with PDF including models and anomalies"""
        if not self.check_admin():
            return

        period_days = int(args.period.rstrip('d'))
        console.print(f"[cyan]Generating system report for the last {args.period}...[/cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Collecting data...", total=6)
            
            end_date = datetime.now()
            start_date = end_date - timedelta(days=period_days)
            
            progress.update(task, advance=1, description="Getting detection summary...")
            try:
                detection_summary = self.db.get_detection_summary(None, period_days)
            except Exception as e:
                console.print(f"[yellow]Warning: Could not get detection summary: {e}[/yellow]")
                detection_summary = []
            
            progress.update(task, advance=1, description="Getting user logs...")
            try:
                # Get audit logs for user activity - this should include ALL actions
                audit_logs = self.db.get_audit_logs(period_days)
                # Filter out None values
                audit_logs = [log for log in audit_logs if log is not None]
            except Exception as e:
                console.print(f"[yellow]Warning: Could not get audit logs: {e}[/yellow]")
                audit_logs = []
            
            progress.update(task, advance=1, description="Getting training logs...")
            try:
                # Get model training events separately if needed
                training_events = self.db.get_audit_logs(period_days)
                training_events = [log for log in training_events if log and log.get('action') == 'model_train']
            except Exception as e:
                console.print(f"[yellow]Warning: Could not get training logs: {e}[/yellow]")
                training_events = []
            
            progress.update(task, advance=1, description="Getting recent anomalies...")
            try:
                recent_anomalies = self.db.get_recent_anomalies(period_days, limit=20)
            except Exception as e:
                console.print(f"[yellow]Warning: Could not get recent anomalies: {e}[/yellow]")
                recent_anomalies = []
            
            progress.update(task, advance=1, description="Getting all models...")
            try:
                all_models = self.db.get_all_models()
            except Exception as e:
                console.print(f"[yellow]Warning: Could not get models: {e}[/yellow]")
                all_models = []

            progress.update(task, advance=1, description="Getting all detections...")
            try:
                all_detections = self.db.get_all_detections(period_days)
            except Exception as e:
                console.print(f"[yellow]Warning: Could not get detections: {e}[/yellow]")
                all_detections = []
            
            progress.update(task, advance=1, description="Compiling report...")

        # Calculate totals safely
        total_flows = 0
        total_anomalies = 0
        for d in detection_summary:
            if d:
                total_flows += d.get('total_flows', 0) if d.get('total_flows') else 0
                total_anomalies += d.get('total_anomalies', 0) if d.get('total_anomalies') else 0

        # Safely calculate anomaly rate
        anomaly_rate = (total_anomalies / total_flows) if total_flows > 0 else 0

        # Display comprehensive summary
        console.print(Panel.fit(
            f"[bold cyan]System Report Summary[/bold cyan]\n"
            f"────────────────────────────\n"
            f"Period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}\n"
            f"Total Flows Analyzed: [green]{total_flows:,}[/green]\n"
            f"Total Anomalies: [yellow]{total_anomalies:,}[/yellow]\n"
            f"Anomaly Rate: [magenta]{anomaly_rate:.2%}[/magenta]\n",
            title="Report Summary",
            border_style="cyan"
        ))

        # Display all detections
        if all_detections:
            det_table = Table(title=f"All Detections (Last {args.period})", box=ROUNDED)
            det_table.add_column("ID", style="cyan")
            det_table.add_column("User", style="green")
            det_table.add_column("Date", style="blue")
            det_table.add_column("Total Flows", justify="right")
            det_table.add_column("Anomalies", justify="right")
            det_table.add_column("Model ID", justify="right")
        
            for det in all_detections[:20]:
                if det:
                    created_at = det.get('created_at')
                    date_str = created_at.strftime('%Y-%m-%d %H:%M') if created_at and hasattr(created_at, 'strftime') else 'N/A'
                    det_table.add_row(
                        str(det.get('id', 'N/A')),
                        det.get('username', 'N/A'),
                        date_str,
                        f"{det.get('total_flows', 0):,}",
                        str(det.get('anomalies_detected', 0)),
                        str(det.get('model_id', 'N/A'))
                    )
            console.print(det_table)
            console.print(f"[dim]Showing {min(20, len(all_detections))} of {len(all_detections)} detections[/dim]")
        else:
            console.print("[yellow]No detection data found for the specified period[/yellow]")

        # Display all models - FIXED: Handle None accuracy values
        if all_models:
            model_table = Table(title="All Models in System", box=ROUNDED)
            model_table.add_column("ID", style="cyan")
            model_table.add_column("Name", style="green")
            model_table.add_column("User", style="yellow")
            model_table.add_column("Type", style="blue")
            model_table.add_column("Accuracy", justify="right")
            model_table.add_column("Samples", justify="right")
            model_table.add_column("Created", style="magenta")
        
            for model in all_models[:20]:
                if model:
                    name = model.get('name', 'N/A')
                    display_name = name[:30] + "..." if len(name) > 30 else name
                    accuracy = model.get('accuracy')
                    if accuracy is not None:
                        accuracy_str = f"{accuracy:.2%}"
                    else:
                        accuracy_str = "N/A"
                    
                    training_samples = model.get('training_samples')
                    samples_str = f"{training_samples:,}" if training_samples else "N/A"
                    
                    created_at = model.get('created_at')
                    created_str = created_at.strftime('%Y-%m-%d') if created_at and hasattr(created_at, 'strftime') else 'N/A'
                    
                    model_table.add_row(
                        str(model.get('id', 'N/A')),
                        display_name,
                        model.get('username', 'N/A'),
                        model.get('model_type', 'rnsa_knn'),
                        accuracy_str,
                        samples_str,
                        created_str
                    )
            console.print(model_table)
        else:
            console.print("[yellow]No models found in the system[/yellow]")

        # Display User Logs (same as audit logs format)
        if audit_logs:
            console.print("\n[bold cyan]User Logs[/bold cyan]")
            log_table = Table(title=f"User Activity Logs - Last {args.period}", box=ROUNDED)
            log_table.add_column("ID", style="dim", width=6)
            log_table.add_column("Timestamp", style="cyan", width=20)
            log_table.add_column("User", style="green", width=15)
            log_table.add_column("Action", style="yellow", width=20)
            log_table.add_column("Resource", style="blue", width=30)
            log_table.add_column("Status", style="magenta", width=10)

            for log in audit_logs[:50]:  # Show first 50
                timestamp = log['created_at'].strftime('%Y-%m-%d %H:%M:%S') if hasattr(log['created_at'], 'strftime') else str(log.get('created_at', ''))[:19]
                username = log.get('username') or 'System'
                resource = log.get('resource') or '-'
            
                # Truncate long resource names
                if len(resource) > 25:
                    resource = resource[:22] + '...'
            
                log_table.add_row(
                    str(log.get('id', '')),
                    timestamp,
                    username,
                    log.get('action', ''),
                    resource,
                    log.get('status', 'success')
                )

            console.print(log_table)
            console.print(f"[dim]Showing {min(50, len(audit_logs))} of {len(audit_logs)} logs[/dim]")
            
            # Show action summary
            from collections import Counter
            actions = Counter([log.get('action', '') for log in audit_logs])

            summary_table = Table(title="Action Summary", box=ROUNDED)
            summary_table.add_column("Action", style="cyan")
            summary_table.add_column("Count", style="green", justify="right")

            for action, count in actions.most_common(10):
                summary_table.add_row(action, str(count))

            console.print(summary_table)
        else:
            console.print("[yellow]No user activity logs found for the specified period[/yellow]")

        # Display recent anomalies - FIXED: Handle None confidence values
        if recent_anomalies:
            anomaly_table = Table(title="Recent Anomalies", box=ROUNDED)
            anomaly_table.add_column("Detected At", style="cyan")
            anomaly_table.add_column("Flow ID", style="yellow")
            anomaly_table.add_column("Confidence", justify="right")
            anomaly_table.add_column("Severity")
        
            for anomaly in recent_anomalies[:10]:
                if anomaly:
                    detected_at = anomaly.get('detected_at')
                    detected_str = detected_at.strftime('%Y-%m-%d %H:%M') if detected_at and hasattr(detected_at, 'strftime') else str(detected_at) if detected_at else 'N/A'
                    
                    confidence = anomaly.get('confidence', 0)
                    confidence_str = f"{confidence:.2f}" if confidence is not None else "0.00"
                    
                    anomaly_table.add_row(
                        detected_str,
                        str(anomaly.get('index', 'N/A')),
                        confidence_str,
                        anomaly.get('severity', 'Medium')
                    )
            console.print(anomaly_table)
        else:
            console.print("[yellow]No anomalies detected in the specified period[/yellow]")

        # Prepare report data for PDF
        report_data = {
            "report_period": {
                "start": start_date.strftime('%Y-%m-%d'),
                "end": end_date.strftime('%Y-%m-%d'),
                "days": period_days
            },
            "detection_summary": {
                "total_flows_analyzed": total_flows,
                "total_anomalies_detected": total_anomalies,
                "detection_rate": anomaly_rate,
            },
            "user_logs": audit_logs,  # Changed from user_activity to user_logs
            "recent_anomalies": recent_anomalies[:10],
            "all_models": all_models,
            "all_detections": all_detections
        }

        # Generate PDF if requested
        if args.output:
            try:
                from .utils import generate_pdf_report
                generate_pdf_report(report_data, args.output)
                console.print(f"[green]✓ Full report saved to: {args.output}[/green]")
            except Exception as e:
                console.print(f"[red]Failed to generate PDF: {e}[/red]")
                import traceback
                console.print(traceback.format_exc())
 
    def handle_detect(self, args):
        """Handle anomaly detection with feature alignment - works with both core and custom features"""
        
        if not self.check_permission('run_detection'):
            return

        if not os.path.exists(args.input):
            console.print(f"[red]Input file not found: {args.input}[/red]")
            return
        
        # ========== ADD SECURITY VALIDATION ==========
        # Check rate limit
        is_allowed, remaining = self.check_rate_limit('detect')
        if not is_allowed:
            console.print(f"[red]Rate limit exceeded. Only {remaining} requests remaining.[/red]")
            return
        
        # Validate input file with security checks
        file_ext = os.path.splitext(args.input)[1].lower()
        if file_ext == '.json':
            # Validate JSON file
            is_valid, message, json_data = self.validate_input_file_secure(args.input, 'json')
            if not is_valid:
                console.print(f"[red]Security validation failed: {message}[/red]")
                self.db.log_audit_event(
                    user_id=self.auth.current_user['id'],
                    username=self.auth.current_user['username'],
                    action="security_violation",
                    resource=args.input,
                    status="blocked",
                    details={"reason": message, "type": "invalid_json"}
                )
                return
            # For JSON, we need to convert to DataFrame for processing
            if isinstance(json_data, dict) and 'data' in json_data:
                df = pd.DataFrame(json_data['data'])
            elif isinstance(json_data, list):
                df = pd.DataFrame(json_data)
            else:
                df = pd.DataFrame([json_data]) if json_data else pd.DataFrame()
            console.print(f"[cyan]Loaded {len(df)} records from JSON file[/cyan]")
            
        elif file_ext == '.csv':
            # Validate CSV file
            is_valid, message, df_preview = self.validate_input_file_secure(args.input, 'csv')
            if not is_valid:
                console.print(f"[red]Security validation failed: {message}[/red]")
                self.db.log_audit_event(
                    user_id=self.auth.current_user['id'],
                    username=self.auth.current_user['username'],
                    action="security_violation",
                    resource=args.input,
                    status="blocked",
                    details={"reason": message, "type": "invalid_csv"}
                )
                return
            # Load full CSV
            df = pd.read_csv(args.input)
            console.print(f"[cyan]Loaded {len(df)} records from CSV file[/cyan]")
            
        else:
            console.print(f"[red]Unsupported file type: {file_ext}. Please use .csv or .json[/red]")
            return
        # ========== END SECURITY VALIDATION ==========

        # Load model
        model = None
        model_id = None
        custom_features_used = False
        model_features_info = None
        
        if args.model_id:
            # Load from database
            model_data = self.db.get_model(args.model_id, self.auth.current_user['id'])
            if not model_data:
                console.print(f"[red]Model ID {args.model_id} not found[/red]")
                return

            model_path = model_data['model_path']
            model_id = args.model_id
            
            # Get features info from database
            if model_data.get('features_used'):
                model_features_info = model_data['features_used']
                custom_features_used = model_features_info.get('custom_features_used', False)
                console.print(f"[cyan]Model features info: {model_features_info.get('features_list', []) if model_features_info else 'Unknown'}[/cyan]")
            elif model_data.get('features'):
                features_list = model_data['features']
                if isinstance(features_list, str):
                    features_list = json.loads(features_list)
                custom_features_used = features_list is not None and len(features_list) != 10
                console.print(f"[cyan]Model features: {features_list}[/cyan]")
        
            # Check if path exists
            if not os.path.exists(model_path):
                console.print(f"[red]Model file not found: {model_path}[/red]")
            
                # Try alternative paths
                possible_paths = [
                    model_path,
                    os.path.join("saved_models", os.path.basename(model_path)),
                    os.path.basename(model_path),
                ]
            
                found = False
                for path in possible_paths:
                    if os.path.exists(path):
                        model_path = path
                        found = True
                        break
            
                if not found:
                    console.print("[red]Could not locate model file[/red]")
                    return

            try:
                model = IntrusionDetectionModel.load(model_path)
            except Exception as e:
                console.print(f"[red]Error loading model: {e}[/red]")
                return

        elif args.model_path:
            # Load from file path
            if not os.path.exists(args.model_path):
                console.print(f"[red]Model file not found: {args.model_path}[/red]")
                return

            try:
                model = IntrusionDetectionModel.load(args.model_path)
            except Exception as e:
                console.print(f"[red]Error loading model: {e}[/red]")
                return

        else:
            console.print("[red]Please specify either --model-id or --model-path[/red]")
            return

        # Show model info
        console.print(f"[cyan]Model loaded: {os.path.basename(model_path)}[/cyan]")
        feature_info = model.get_feature_summary()
        
        # Determine if custom features were used
        if custom_features_used or (model.feature_names and len(model.feature_names) != 10):
            console.print(f"[cyan]Model uses custom features: {model.feature_names if model.feature_names else feature_info.get('core_features', [])}[/cyan]")
            console.print(f"[cyan]Number of features: {len(model.feature_names) if model.feature_names else feature_info.get('features_count', 0)}[/cyan]")
        else:
            console.print(f"[cyan]Model expects {feature_info['features_count']} core features (with mapping)[/cyan]")

        # Apply custom threshold if provided
        if hasattr(args, 'threshold') and args.threshold is not None:
            original_threshold = model.threshold
            model.threshold = args.threshold
            console.print(f"[cyan]Using custom threshold: {args.threshold} (default was {original_threshold})[/cyan]")

        # Perform detection
        import time
        start_time = time.time()
        
        self.db.set_long_timeout()
        
        detection_id = None
        detection_success = False
        anomalies_count = 0
        total_flows = 0

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                task = progress.add_task("[cyan]Analyzing traffic...", total=None)

                # Load data
                df = pd.read_csv(args.input)
                console.print(f"[cyan]Loaded {len(df)} records from {args.input}[/cyan]")
            
                # Check if data has labels
                has_labels = False
                y_true = None
                label_column_name = None

                # Look for label columns (case-insensitive)
                possible_label_cols = ['label', 'Label', ' Label', 'attack_type', 'class', 'Label.1', 'LABEL', 'attack', 'Attack']
                for col in possible_label_cols:
                    if col in df.columns:
                        has_labels = True
                        label_column_name = col
                
                        # Get original labels first
                        original_labels = df[col].values
                
                        console.print(f"[green]✓ Found label column: '{col}'[/green]")
                        console.print(f"  Original labels: {np.unique(original_labels)}")

                        # Convert string labels to binary (0 for normal/benign, 1 for attack/malicious)
                        if original_labels.dtype == 'object' or isinstance(original_labels[0], str):
                            normal_terms = ['benign', 'Benign', 'BENIGN', 'normal', 'Normal', '0', 'false', 'no', 'legitimate']
                    
                            y_true_binary = []
                            for val in original_labels:
                                val_str = str(val).lower().strip()
                                is_normal = False
                                for term in normal_terms:
                                    if term in val_str:
                                        is_normal = True
                                        break
                            
                                if is_normal:
                                    y_true_binary.append(0)
                                else:
                                    y_true_binary.append(1)
                    
                            y_true = np.array(y_true_binary)
                            console.print(f"  Converted to binary: 0=normal, 1=attack")
                            console.print(f"  Class distribution: Normal={np.sum(y_true==0)}, Attack={np.sum(y_true==1)}")
                        else:
                            y_true = original_labels.astype(np.int32)

                        break

                if not has_labels:
                    console.print("[yellow]No label column found. Will perform unsupervised detection only.[/yellow]")
                    df_features = df.copy()
                    y_true = None
                else:
                    df_features = df.drop(columns=[label_column_name])
                
                # Use model's preprocessing (handle custom features automatically)
                df_features.replace([np.inf, -np.inf], np.nan, inplace=True)
                df_features.dropna(inplace=True)
            
                X = model.preprocess_data(df_features, fit_scaler=False)
        
                # Detect anomalies
                predictions, confidence_scores = model.predict(X)
        
                # Apply threshold (using model's threshold which may have been updated)
                thresholded_predictions = (confidence_scores >= model.threshold).astype(int)
        
                # Calculate execution time
                execution_time = time.time() - start_time
        
                # Prepare results
                if has_labels and y_true is not None:
                    if len(y_true) != len(predictions):
                        console.print(f"[yellow]Warning: Label length ({len(y_true)}) doesn't match features ({len(predictions)}). Truncating...[/yellow]")
                        min_len = min(len(y_true), len(predictions))
                        y_true = y_true[:min_len]
                        thresholded_predictions = thresholded_predictions[:min_len]
                        confidence_scores = confidence_scores[:min_len]
                    
                    results = self.prepare_detection_results_with_labels(
                        df_features, thresholded_predictions, confidence_scores, y_true, model, execution_time
                    )
                else:
                    results = self.prepare_detection_results(
                        df_features, thresholded_predictions, confidence_scores, model, execution_time
                    )
        
                # Add feature alignment info
                results['feature_alignment'] = {
                    'features_used': model.CORE_FEATURES,
                    'features_count': len(model.CORE_FEATURES),
                    'custom_features': custom_features_used or len(model.CORE_FEATURES) != 10,
                    'feature_mapping': model.feature_mapping
                }

                # Convert to JSON serializable
                serializable_results = self.make_json_serializable(results)
        
                # Save to database
                try:
                    save_db = DatabaseManager()
                    detection_id = save_db.save_detection(
                        user_id=self.auth.current_user['id'],
                        model_id=model_id,
                        input_file=args.input,
                        results=serializable_results
                    )
                    save_db.close()
                    detection_success = True
                    anomalies_count = results['anomalies_detected']
                    total_flows = results['total_flows']
                except Exception as e:
                    console.print(f"[yellow]Warning: Could not save detection to database: {e}[/yellow]")
        
                progress.update(task, completed=100)
            
            # Log detection event
            self.db.log_audit_event(
                user_id=self.auth.current_user['id'],
                username=self.auth.current_user['username'],
                action="detect",
                resource=args.input,
                status="success" if detection_success else "partial",
                details={
                    "model_id": model_id,
                    "total_flows": total_flows,
                    "anomalies_detected": anomalies_count,
                    "execution_time_seconds": execution_time,
                    "detection_id": detection_id,
                    "threshold_used": model.threshold,
                    "custom_features_used": custom_features_used or len(model.CORE_FEATURES) != 10,
                    "features_count": len(model.CORE_FEATURES)
                }
            )
            
        except Exception as e:
            # Log failed detection attempt
            self.db.log_audit_event(
                user_id=self.auth.current_user['id'],
                username=self.auth.current_user['username'],
                action="detect",
                resource=args.input,
                status="failed",
                details={"error": str(e)}
            )
            console.print(f"[red]Detection failed: {e}[/red]")
            if hasattr(self.args, 'verbose') and self.args.verbose:
                console.print(traceback.format_exc())
            return

        # Restore original threshold if changed
        if hasattr(args, 'threshold') and args.threshold is not None:
            model.threshold = original_threshold

        # Display results
        console.print(f"[green]✓ Detection analysis completed[/green]")
        console.print(f"[yellow]⚠️ Anomalies detected: {results['anomalies_detected']} / {results['total_flows']}[/yellow]")
        
        # Show detection summary in a table
        if results['anomalies']:
            console.print(f"\n[bold cyan]DETECTED ANOMALIES (First 50)[/bold cyan]")
            
            # Create a Rich table for anomalies
            anomaly_table = Table(title="Detected Anomalies", box=ROUNDED, show_header=True, header_style="bold magenta")
            anomaly_table.add_column("Index", style="cyan", width=8)
            anomaly_table.add_column("Confidence", style="yellow", width=12, justify="right")
            anomaly_table.add_column("Severity", style="red", width=10)
            anomaly_table.add_column("Top Features", style="green", width=50)
            
            for anomaly in results['anomalies'][:50]:
                # Get feature values as string
                feature_str = ""
                if 'top_features' in anomaly:
                    features = anomaly['top_features']
                    feature_items = []
                    for feat_name, feat_val in list(features.items())[:5]:  # Show top 5 features
                        # Format feature name nicely (use display names for core features)
                        nice_names = {
                            'dur': 'Duration', 'spkts': 'Src Pkts', 'dpkts': 'Dst Pkts',
                            'sbytes': 'Src Bytes', 'dbytes': 'Dst Bytes', 'rate': 'Flow Rate',
                            'smean': 'Src Pkt Mean', 'dmean': 'Dst Pkt Mean',
                            'swin': 'Src Window', 'dwin': 'Dst Window'
                        }
                        display_name = nice_names.get(feat_name, feat_name)
                        if isinstance(feat_val, (int, float)):
                            feature_items.append(f"{display_name}: {feat_val:.2f}")
                        else:
                            feature_items.append(f"{display_name}: {feat_val}")
                    feature_str = ", ".join(feature_items)
                
                # Color code severity
                severity_color = "red" if anomaly['severity'] in ['Critical', 'High'] else "yellow" if anomaly['severity'] == 'Medium' else "green"
                
                anomaly_table.add_row(
                    str(anomaly['index']),
                    f"{anomaly['confidence']:.4f}",
                    f"[{severity_color}]{anomaly['severity']}[/{severity_color}]",
                    feature_str
                )
            
            console.print(anomaly_table)
            
            if len(results['anomalies']) > 50:
                console.print(f"[dim]... and {len(results['anomalies']) - 50} more anomalies[/dim]")
        else:
            console.print("[green]✓ No anomalies detected![/green]")

        # Show metrics if available in a table
        if 'accuracy' in results:
            console.print(f"\n[bold cyan]Performance Metrics[/bold cyan]")
            
            metrics_table = Table(title="Model Performance", box=ROUNDED, show_header=True, header_style="bold blue")
            metrics_table.add_column("Metric", style="cyan", width=25)
            metrics_table.add_column("Value", style="green", width=20, justify="right")
            
            metrics_table.add_row("Accuracy", f"{results['accuracy']:.2%}")
            metrics_table.add_row("Precision", f"{results['precision']:.2%}")
            metrics_table.add_row("Recall (Detection Rate)", f"{results['recall']:.2%}")
            metrics_table.add_row("F1 Score", f"{results['f1_score']:.2%}")
            metrics_table.add_row("False Positive Rate", f"{results['false_positive_rate']:.2%}")
            
            console.print(metrics_table)
            
            if 'true_positives' in results:
                console.print(f"\n[bold cyan]Confusion Matrix[/bold cyan]")
                
                # Create confusion matrix table
                cm_table = Table(title="Confusion Matrix", box=ROUNDED, show_header=True, header_style="bold blue")
                cm_table.add_column("", style="cyan", width=15)
                cm_table.add_column("Predicted Normal", style="green", width=18, justify="center")
                cm_table.add_column("Predicted Attack", style="red", width=18, justify="center")
                
                cm_table.add_row(
                    "[bold]Actual Normal[/bold]",
                    f"[green]{results['true_negatives']:,}[/green] (TN)",
                    f"[red]{results['false_positives']:,}[/red] (FP)"
                )
                cm_table.add_row(
                    "[bold]Actual Attack[/bold]",
                    f"[green]{results['false_negatives']:,}[/green] (FN)",
                    f"[red]{results['true_positives']:,}[/red] (TP)"
                )
                
                console.print(cm_table)

        # Show execution time if available
        if 'execution_time' in results:
            console.print(f"\n[dim]Execution time: {results['execution_time']}[/dim]")

        # Save results if requested
        if args.output:
            try:
                serializable_results = self.make_json_serializable(results)
                with open(args.output, 'w') as f:
                    json.dump(serializable_results, f, indent=2)
                console.print(f"[green]✓ Full results saved to: {args.output}[/green]")
            except Exception as e:
                console.print(f"[red]Failed to save results to file: {e}[/red]")

        # Tell user how to get explanations
        if detection_id:
            console.print(f"\n[yellow]For full explanations, use:[/yellow]")
            console.print(f"[cyan]  vigilante explain --detection-id {detection_id}[/cyan]")

    def prepare_detection_results(self, df, predictions, confidence_scores, model, execution_time=None):
        """Prepare detection results in structured format with JSON serializable types - NO reconstruction errors"""
        anomalies = []
        anomaly_indices = np.where(predictions == 1)[0]
        
        for idx in anomaly_indices:
            confidence = float(confidence_scores[idx]) if idx < len(confidence_scores) else 0.5
        
            anomaly = {
                'index': int(idx),
                'confidence': confidence,
                'severity': self.calculate_severity(confidence),
            }
        
            # Add feature values for context
            if idx < len(df):
                row = df.iloc[idx]
                top_features = {}
                feature_names = model.feature_names if model.feature_names else []
            
                # Get all core features
                for i, feat in enumerate(feature_names[:10]):  # Show all 10 core features
                    if i < len(row):
                        val = row.iloc[i] if hasattr(row, 'iloc') else row[i]
                        if isinstance(val, (int, float)):
                            top_features[feat] = float(val)
                        else:
                            top_features[feat] = str(val)
                anomaly['top_features'] = top_features
        
            anomalies.append(anomaly)

        # Calculate metrics
        total_flows = int(len(predictions))
        anomalies_detected = int(len(anomalies))
        detection_rate = float(anomalies_detected / total_flows) if total_flows > 0 else 0.0

        result = {
            'total_flows': total_flows,
            'anomalies_detected': anomalies_detected,
            'detection_rate': detection_rate,
            'anomalies': anomalies[:100],
            'mean_confidence': float(np.mean(confidence_scores)) if len(confidence_scores) > 0 else 0,
            'std_confidence': float(np.std(confidence_scores)) if len(confidence_scores) > 0 else 0,
            'threshold': float(model.threshold),
            'detectors_used': len(model.model.detectors) if hasattr(model.model, 'detectors') else 0,
            'features_used': model.feature_names,
            'metrics': model.metrics if hasattr(model, 'metrics') else {}
        }

        # Add execution time if provided
        if execution_time is not None:
            result['execution_time'] = self.format_execution_time(execution_time)
            result['execution_time_seconds'] = float(execution_time)

        return result

    def prepare_detection_results_with_labels(self, df, predictions, confidence_scores, y_true, model, execution_time=None):
        """Prepare detection results with full metrics using ground truth labels - CASE-INSENSITIVE like RNSA_KNN_training"""
        from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                                    f1_score, confusion_matrix)
        
        # Ensure y_true is numpy array and properly formatted
        if isinstance(y_true, list):
            y_true = np.array(y_true)
        
        # Ensure y_true is binary (0/1) and int type
        if y_true.dtype not in [np.int32, np.int64, int]:
            try:
                # Try to convert to int
                y_true = y_true.astype(np.int32)
            except:
                # If conversion fails, map string labels to binary
                normal_terms = ['benign', 'Benign', 'BENIGN', 'normal', 'Normal', '0', 'false', 'no', 'legitimate']
                y_true_binary = []
                for val in y_true:
                    val_str = str(val).lower().strip()
                    is_normal = False
                    for term in normal_terms:
                        if term in val_str:
                            is_normal = True
                            break
                    if is_normal:
                        y_true_binary.append(0)
                    else:
                        y_true_binary.append(1)
                y_true = np.array(y_true_binary, dtype=np.int32)
        
        # Ensure predictions are int type
        predictions = predictions.astype(np.int32)
        
        # Ensure predictions and y_true have the same length
        min_len = min(len(predictions), len(y_true))
        if len(predictions) != len(y_true):
            console.print(f"[yellow]Warning: Truncating to match lengths: predictions={len(predictions)}, y_true={len(y_true)}[/yellow]")
            predictions = predictions[:min_len]
            confidence_scores = confidence_scores[:min_len]
            y_true = y_true[:min_len]
        
        anomalies = []
        anomaly_indices = np.where(predictions == 1)[0]

        for idx in anomaly_indices:
            confidence = float(confidence_scores[idx]) if idx < len(confidence_scores) else 0.5
        
            anomaly = {
                'index': int(idx),
                'confidence': confidence,
                'severity': self.calculate_severity(confidence),
            }
        
            # Add feature values for context
            if idx < len(df):
                row = df.iloc[idx] if hasattr(df, 'iloc') else df[idx]
                top_features = {}
                feature_names = model.feature_names if model.feature_names else []
            
                # Get all core features
                for i, feat in enumerate(feature_names[:10]):  # Show all 10 core features
                    if i < len(row):
                        val = row.iloc[i] if hasattr(row, 'iloc') else row[i]
                        if isinstance(val, (int, float)):
                            top_features[feat] = float(val)
                        else:
                            top_features[feat] = str(val)
                anomaly['top_features'] = top_features
        
            anomalies.append(anomaly)

        # Calculate confusion matrix
        cm = confusion_matrix(y_true, predictions)

        if cm.shape == (2, 2):
            TN, FP, FN, TP = cm.ravel()
        
            # Calculate all metrics
            accuracy = accuracy_score(y_true, predictions)
            precision = precision_score(y_true, predictions, zero_division=0)
            recall = recall_score(y_true, predictions, zero_division=0)
            f1 = f1_score(y_true, predictions, zero_division=0)
        
            # Detection rate = TP / (TP + FN) = recall
            detection_rate = recall
        
            # False positive rate = FP / (FP + TN)
            false_positive_rate = FP / (FP + TN) if (FP + TN) > 0 else 0
        
        else:
            # Handle case where confusion matrix isn't 2x2
            accuracy = precision = recall = f1 = detection_rate = false_positive_rate = 0
            TP = FP = TN = FN = 0

        total_flows = int(len(predictions))
        anomalies_detected = int(len(anomalies))

        result = {
            'total_flows': total_flows,
            'anomalies_detected': anomalies_detected,
            'detection_rate': float(detection_rate),
            'false_positive_rate': float(false_positive_rate),
            'anomalies': anomalies[:100],
            'mean_confidence': float(np.mean(confidence_scores)) if len(confidence_scores) > 0 else 0,
        
            # Classification metrics
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
        
            # Confusion matrix values
            'true_positives': int(TP),
            'false_positives': int(FP),
            'true_negatives': int(TN),
            'false_negatives': int(FN),
        
            # Model metrics
            'metrics': model.metrics if hasattr(model, 'metrics') else {}
        }

        if execution_time is not None:
            result['execution_time'] = self.format_execution_time(execution_time)
            result['execution_time_seconds'] = float(execution_time)

        return result

    def calculate_roc_metrics(self, y_true, y_scores, algorithm_name):
        """
        Calculate detailed ROC metrics for an algorithm
        """
        from sklearn.metrics import roc_curve, auc, confusion_matrix
        import numpy as np
    
        # Calculate ROC curve
        fpr, tpr, thresholds = roc_curve(y_true, y_scores)

        # Calculate AUC
        roc_auc = auc(fpr, tpr)

        # Find optimal threshold (Youden's J statistic)
        threshold = tpr - fpr
        optimal_idx = np.argmax(threshold)
        optimal_threshold = thresholds[optimal_idx]

        # Calculate metrics at optimal threshold
        y_pred_optimal = (y_scores >= optimal_threshold).astype(int)
        cm = confusion_matrix(y_true, y_pred_optimal)
    
        if cm.shape == (2, 2):
            TN, FP, FN, TP = cm.ravel()
            detection_rate_optimal = TP / (TP + FN) if (TP + FN) > 0 else 0
            false_alarm_rate_optimal = FP / (FP + TN) if (FP + TN) > 0 else 0
            precision_optimal = TP / (TP + FP) if (TP + FP) > 0 else 0
        else:
            detection_rate_optimal = false_alarm_rate_optimal = precision_optimal = 0

        console.print(f"\n{'-'*60}")
        console.print(f"[bold cyan]ROC Analysis for {algorithm_name}[/bold cyan]")
        console.print(f"{'-'*60}")
        console.print(f"AUC: [green]{roc_auc:.4f}[/green]")
        console.print(f"Optimal Threshold: [yellow]{optimal_threshold:.4f}[/yellow]")
        console.print(f"Detection Rate at Optimal Threshold: {detection_rate_optimal:.4f}")
        console.print(f"False Alarm Rate at Optimal Threshold: {false_alarm_rate_optimal:.4f}")
        console.print(f"Precision at Optimal Threshold: {precision_optimal:.4f}")

        return {
            'fpr': fpr.tolist(),
            'tpr': tpr.tolist(),
            'thresholds': thresholds.tolist(),
            'auc': float(roc_auc),
            'optimal_threshold': float(optimal_threshold),
            'optimal_dr': float(detection_rate_optimal),
            'optimal_far': float(false_alarm_rate_optimal),
            'optimal_precision': float(precision_optimal)
        }

    def plot_roc_curve(self, y_true, y_scores, dataset_name, save_path=None):
        """
        Plot ROC curves for the algorithm
        """
        try:
            import matplotlib.pyplot as plt
            from sklearn.metrics import roc_curve, auc
        
            plt.figure(figsize=(10, 8))

            # Calculate ROC curve
            fpr, tpr, thresholds = roc_curve(y_true, y_scores)

            # Calculate AUC
            roc_auc = auc(fpr, tpr)

            # Plot ROC curve
            plt.plot(fpr, tpr, color='blue', lw=2,
                     label=f'Single Model (AUC = {roc_auc:.4f})')

            # Plot diagonal line (random classifier)
            plt.plot([0, 1], [0, 1], color='gray', lw=1, linestyle='--', 
                     label='Random (AUC = 0.5)')

            # Customize plot
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate (False Alarm Rate)', fontsize=12)
            plt.ylabel('True Positive Rate (Detection Rate)', fontsize=12)
            plt.title(f'ROC Curve for Single Model on {dataset_name}', fontsize=14, fontweight='bold')
            plt.legend(loc="lower right", fontsize=11)
            plt.grid(True, alpha=0.3)

            # Add AUC values in text box
            plt.text(0.6, 0.15, f'AUC: {roc_auc:.4f}',
                     bbox=dict(facecolor='white', alpha=0.8, boxstyle='round,pad=0.5'),
                     fontsize=10)

            plt.tight_layout()
        
            if save_path:
                plt.savefig(save_path, dpi=300, bbox_inches='tight')
                console.print(f"[green]✓ ROC curve saved to: {save_path}[/green]")
        
            plt.show()
        
        except ImportError:
            console.print("[yellow]Matplotlib not available for plotting ROC curve[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Could not plot ROC curve: {e}[/yellow]")

    def alternative_preprocessing(self, df: pd.DataFrame, model) -> np.ndarray:
        """Alternative preprocessing when standard preprocessing fails"""
        console.print("[yellow]Using alternative preprocessing...[/yellow]")
    
        # Select only numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns
    
        if len(numeric_cols) == 0:
            # If no numeric columns, try to convert everything to numeric
            df_numeric = df.apply(pd.to_numeric, errors='coerce').fillna(0)
            numeric_cols = df_numeric.columns
        else:
            df_numeric = df[numeric_cols].copy()
    
        # Fill NaN values
        df_numeric = df_numeric.fillna(0)
        df_numeric = df_numeric.replace([np.inf, -np.inf], 0)
    
        # Use the model's scaler if available
        if hasattr(model, 'scaler') and model.scaler:
            X_scaled = model.scaler.transform(df_numeric)
        elif hasattr(model, 'model') and hasattr(model.model, 'scaler') and model.model.scaler:
            X_scaled = model.model.scaler.transform(df_numeric)
        else:
            # Create new scaler
            from sklearn.preprocessing import MinMaxScaler
            scaler = MinMaxScaler()
            X_scaled = scaler.fit_transform(df_numeric)
    
        console.print(f"[green]✓ Alternative preprocessing complete: {X_scaled.shape}[/green]")
        return X_scaled

    def validate_and_prepare_data(self, df: pd.DataFrame, model) -> pd.DataFrame:
        """Validate and prepare input data for detection"""
        console.print("[cyan]Validating input data...[/cyan]")
    
        # Make a copy to avoid modifying original
        df_processed = df.copy()
    
        # Add flow_id if not present
        if 'flow_id' not in df_processed.columns:
            df_processed = df_processed.reset_index().rename(columns={'index': 'flow_id'})
    
        # Check for label column and remove it if present
        label_cols = ['label', 'Label', ' Label', 'attack_cat', 'Label.1']
        for col in label_cols:
            if col in df_processed.columns:
                df_processed = df_processed.drop(columns=[col])
                console.print(f"[yellow]Removed label column: {col}[/yellow]")
    
        # Check for timestamp columns and remove them
        time_cols = ['timestamp', 'Timestamp', 'timestamp', 'StartTime', 'EndTime', ' Timestamp']
        for col in time_cols:
            if col in df_processed.columns:
                df_processed = df_processed.drop(columns=[col])
    
        # Handle IP address columns
        ip_cols = ['srcip', 'dstip', 'src_ip', 'dst_ip', 'srcip', 'dstip', 
                'Source IP', 'Destination IP', ' Source IP', ' Destination IP']
    
        for col in ip_cols:
            if col in df_processed.columns:
                try:
                    # Convert IP addresses to numeric representation
                    if df_processed[col].dtype == 'object':
                        df_processed[col] = pd.factorize(df_processed[col])[0]
                        console.print(f"[cyan]Converted {col} to numeric[/cyan]")
                except:
                    # If conversion fails, drop the column
                    df_processed = df_processed.drop(columns=[col])
                    console.print(f"[yellow]Dropped problematic column: {col}[/yellow]")
    
        # Handle protocol and port columns
        proto_port_cols = ['proto', 'protocol', 'Protocol', 'sport', 'dport', 
                        'src_port', 'dst_port', ' Source Port', ' Destination Port']
    
        for col in proto_port_cols:
            if col in df_processed.columns:
                try:
                    if df_processed[col].dtype == 'object':
                        # For protocol names (tcp, udp, etc.)
                        if df_processed[col].nunique() < 20:
                            df_processed[col] = pd.factorize(df_processed[col])[0]
                        else:
                            # For port numbers, ensure they're numeric
                            df_processed[col] = pd.to_numeric(df_processed[col], errors='coerce').fillna(0)
                except:
                    df_processed[col] = pd.to_numeric(df_processed[col], errors='coerce').fillna(0)
    
        # Check which model features are available in the data
        if hasattr(model, 'feature_names') and model.feature_names:
            model_features = model.feature_names
            available_features = [f for f in model_features if f in df_processed.columns]
        
            console.print(f"[cyan]Model expects {len(model_features)} features[/cyan]")
            console.print(f"[cyan]Found {len(available_features)} matching features in input data[/cyan]")
        
            if len(available_features) < len(model_features) * 0.3:  # Less than 30% match
                console.print("[yellow]Warning: Low feature match between model and input data[/yellow]")
                console.print("[cyan]Will use all available numeric features[/cyan]")
    
        # Ensure all columns are numeric
        for col in df_processed.columns:
            if df_processed[col].dtype == 'object':
                # Try to convert to numeric
                try:
                    df_processed[col] = pd.to_numeric(df_processed[col], errors='coerce')
                except:
                    # If conversion fails, use factorize for categorical data
                    if df_processed[col].nunique() < 100:
                        df_processed[col] = pd.factorize(df_processed[col])[0]
                    else:
                        # Too many unique values, drop the column
                        df_processed = df_processed.drop(columns=[col])
    
        # Fill any NaN values
        df_processed = df_processed.fillna(0)
    
        # Replace infinite values
        df_processed = df_processed.replace([np.inf, -np.inf], 0)
    
        console.print(f"[green]✓ Data prepared: {len(df_processed)} rows, {len(df_processed.columns)} columns[/green]")
    
        return df_processed

    # Add this new method to format execution time
    def format_execution_time(self, seconds):
        """Format execution time in human-readable format"""
        if seconds < 1:
            return f"{seconds * 1000:.2f} ms"
        elif seconds < 60:
            return f"{seconds:.2f} seconds"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.2f} minutes"
        else:
            hours = seconds / 3600
            return f"{hours:.2f} hours"

    def make_json_serializable(self, obj):
        """Convert numpy and pandas objects to JSON serializable types"""
        if isinstance(obj, dict):
            return {k: self.make_json_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.make_json_serializable(v) for v in obj]
        elif isinstance(obj, tuple):
            return tuple(self.make_json_serializable(v) for v in obj)
        elif isinstance(obj, (np.integer, np.int64, np.int32, np.int8)):
            return int(obj)
        elif isinstance(obj, (np.floating, np.float64, np.float32, np.float16)):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, np.bool_):
            return bool(obj)
        elif pd.isna(obj):
            return None
        elif isinstance(obj, pd.Timestamp):
            return obj.isoformat()
        elif hasattr(obj, 'to_dict'):  # Handle pandas Series/DataFrame
            return obj.to_dict()
        else:
            return obj
    
    def handle_train(self, args):
        """Handle model training with feature alignment"""
        if not self.check_permission('train_models'):
            return

        if not os.path.exists(args.input):
            console.print(f"[red]Input file not found: {args.input}[/red]")
            return
        
        # ========== ADD SECURITY VALIDATION ==========
        # Check rate limit
        is_allowed, remaining = self.check_rate_limit('train')
        if not is_allowed:
            console.print(f"[red]Rate limit exceeded. Only {remaining} requests remaining.[/red]")
            return
        
        # Validate input file with security checks
        file_ext = os.path.splitext(args.input)[1].lower()
        if file_ext not in ['.csv', '.json']:
            console.print(f"[red]Unsupported file type: {file_ext}. Please use .csv or .json[/red]")
            return
        
        if file_ext == '.csv':
            is_valid, message, data = self.validate_input_file_secure(args.input, 'csv')
            if not is_valid:
                console.print(f"[red]Security validation failed: {message}[/red]")
                self.db.log_audit_event(
                    user_id=self.auth.current_user['id'],
                    username=self.auth.current_user['username'],
                    action="security_violation",
                    resource=args.input,
                    status="blocked",
                    details={"reason": message, "type": "invalid_csv", "operation": "train"}
                )
                return
        else:  # .json
            is_valid, message, json_data = self.validate_input_file_secure(args.input, 'json')
            if not is_valid:
                console.print(f"[red]Security validation failed: {message}[/red]")
                self.db.log_audit_event(
                    user_id=self.auth.current_user['id'],
                    username=self.auth.current_user['username'],
                    action="security_violation",
                    resource=args.input,
                    status="blocked",
                    details={"reason": message, "type": "invalid_json", "operation": "train"}
                )
                return
        # ========== END SECURITY VALIDATION ==========

        # Process features
        custom_features = None
        if args.features:
            custom_features = [f.strip() for f in args.features.split(',')]
            console.print(f"[cyan]Using specified features: {custom_features}[/cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Training RNSA+KNN model...", total=100)

            try:
                # Analyze dataset first
                console.print("[cyan]Analyzing dataset features...[/cyan]")
                df_preview = pd.read_csv(args.input, nrows=1000)
                
                from .model import IntrusionDetectionModel
                
                # Load full data to get training samples count
                df_full = pd.read_csv(args.input)
                total_samples = len(df_full)
                
                if custom_features:
                    console.print(f"\n[cyan]Feature Analysis (Custom):[/cyan]")
                    console.print(f"  Custom features specified: {len(custom_features)}")
                    console.print(f"  Features: {custom_features}")
                    
                    # Check which custom features exist in the data
                    available_in_data = [f for f in custom_features if f in df_preview.columns]
                    missing_in_data = [f for f in custom_features if f not in df_preview.columns]
                    
                    console.print(f"  Features found in data: {len(available_in_data)}")
                    if missing_in_data:
                        console.print(f"  [yellow]Missing features (will use zeros): {missing_in_data}[/yellow]")
                else:
                    temp_model = IntrusionDetectionModel()
                    available_features, feature_mapping = temp_model._find_features_in_data(df_preview)
                    console.print(f"\n[cyan]Feature Analysis (Core):[/cyan]")
                    console.print(f"  Core features required: {len(temp_model.CORE_FEATURES)}")
                    console.print(f"  Features found: {len(available_features)}")
                    if feature_mapping:
                        console.print(f"  Feature mapping:")
                        for k, v in list(feature_mapping.items())[:5]:
                            console.print(f"    {k} → {v}")
                
                console.print(f"  Total training samples: {total_samples:,}")
                
                # Train model with custom features if provided
                result = self.trainer.train_model(
                    data_path=args.input,
                    model_name=args.model_name or f"model_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    r_s=0.05,
                    max_detectors=1000,
                    k=5,
                    dataset_name=os.path.basename(args.input),
                    custom_features=custom_features  # Pass custom features to trainer
                )
                
                # Create a fresh database connection for saving the model
                fresh_db = DatabaseManager()
                
                # Prepare metrics with training_samples properly set
                save_metrics = result.get('metrics', {}).copy()
                save_metrics['training_samples'] = result.get('training_samples', total_samples)
                save_metrics['features_count'] = result.get('features_count', len(result.get('features_used', [])))
                
                # Save model to database using fresh connection
                model_id = fresh_db.save_model(
                    user_id=self.auth.current_user['id'],
                    model_name=result['model_name'],
                    model_path=result['model_path'],
                    dataset_name=os.path.basename(args.input),
                    metrics=save_metrics,
                    features=result.get('features_used', custom_features),
                    parameters={
                        'model_type': 'rnsa_knn',
                        'r_s': 0.05,
                        'max_detectors': 1000,
                        'k': 5,
                        'training_samples': total_samples,
                        'custom_features': custom_features if custom_features else None
                    }
                )
                
                # Close the fresh connection
                fresh_db.close()
                
                # Log training event with correct details
                self.db.log_audit_event(
                    user_id=self.auth.current_user['id'],
                    username=self.auth.current_user['username'],
                    action="model_train",
                    resource=args.input,
                    status="success",
                    details={
                        "model_id": model_id, 
                        "model_name": result['model_name'], 
                        "training_samples": total_samples,
                        "features_used": len(result.get('features_used', [])),
                        "custom_features": custom_features is not None,
                        "accuracy": result['metrics'].get('test_accuracy', 0)
                    }
                )
                
                progress.update(task, completed=100)

            except Exception as e:
                # Log failed training attempt
                self.db.log_audit_event(
                    user_id=self.auth.current_user['id'],
                    username=self.auth.current_user['username'],
                    action="model_train",
                    resource=args.input,
                    status="failed",
                    details={"error": str(e)}
                )
                console.print(f"[red]Training failed: {e}[/red]")
                if hasattr(self.args, 'verbose') and self.args.verbose:
                    console.print(traceback.format_exc())
                return

        console.print(f"[green]✓ RNSA+KNN Model trained successfully[/green]")
        console.print(f"Model ID: [cyan]{model_id}[/cyan]")
        console.print(f"Model saved to: [cyan]{result['model_path']}[/cyan]")
        console.print(f"Training samples: [cyan]{total_samples:,}[/cyan]")
        console.print(f"Features used: [cyan]{len(result.get('features_used', []))}[/cyan]")

        # Show metrics
        self.display_training_metrics(result['metrics'])

        # Show feature summary
        if 'feature_analysis' in result:
            fa = result['feature_analysis']
            console.print(f"\n[cyan]Feature Summary:[/cyan]")
            if fa.get('custom_features_used'):
                console.print(f"  Custom features mode: enabled")
                console.print(f"  Features used: {fa.get('available_features', [])}")
            else:
                console.print(f"  Coverage: {fa.get('coverage', 0):.1f}%")
                console.print(f"  Features found: {len(fa.get('available_features', []))}")

    # Show RNSA+KNN specific metrics
    def display_training_metrics(self, metrics):
        """Display training metrics for RNSA+KNN"""
        table = Table(title="RNSA+KNN Training Metrics", box=ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
    
        if 'train_accuracy' in metrics:
            table.add_row("Train Accuracy", f"{metrics['train_accuracy']:.4f}")
        if 'test_accuracy' in metrics:
            table.add_row("Test Accuracy", f"{metrics['test_accuracy']:.4f}")
        if 'detection_rate' in metrics:
            table.add_row("Detection Rate", f"{metrics['detection_rate']:.4f}")
        if 'false_alarm_rate' in metrics:
            table.add_row("False Alarm Rate", f"{metrics['false_alarm_rate']:.4f}")
        if 'auc' in metrics:
            table.add_row("AUC", f"{metrics['auc']:.4f}")
        if 'optimal_dr' in metrics:
            table.add_row("Optimal Detection Rate", f"{metrics['optimal_dr']:.4f}")
        if 'optimal_far' in metrics:
            table.add_row("Optimal False Alarm Rate", f"{metrics['optimal_far']:.4f}")
        if 'detectors' in metrics:
            table.add_row("Detectors Generated", str(metrics['detectors']))
        if 'precision' in metrics:
            table.add_row("Precision", f"{metrics['precision']:.4f}")
        if 'recall' in metrics:
            table.add_row("Recall", f"{metrics['recall']:.4f}")
        if 'f1_score' in metrics:
            table.add_row("F1 Score", f"{metrics['f1_score']:.4f}")
    
        console.print(table)
    
    # Summary Command
    def handle_summary(self, args):
        """Handle detection summary"""
        if not self.check_permission('view_summary'):
            return
        
        # Parse period
        period_days = int(args.period.rstrip('d'))
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description="Aggregating detection results...", total=None)
            
            # Get summary from database
            summary = self.db.get_detection_summary(self.auth.current_user['id'], period_days)
            
            # Get detailed anomalies
            anomalies = self.db.get_user_anomalies(self.auth.current_user['id'], period_days)
        
        if not summary:
            console.print(f"[yellow]No detection data found for the last {args.period}[/yellow]")
            return
        
        # Create summary table
        table = Table(title=f"Detection Summary - Last {args.period}", box=ROUNDED)
        table.add_column("Date", style="cyan")
        table.add_column("Total Flows", justify="right", style="green")
        table.add_column("Total Anomalies", justify="right", style="yellow")
        table.add_column("Anomaly Rate", justify="right", style="magenta")
        
        total_flows = 0
        total_anomalies = 0
        
        for day in summary:
            date_str = day['date'].strftime('%Y-%m-%d')
            flows = day.get('total_flows', 0)
            anomalies_count = day.get('total_anomalies', 0)
            rate = anomalies_count / flows if flows > 0 else 0
            
            table.add_row(
                date_str,
                f"{flows:,}",
                str(anomalies_count),
                f"{rate:.2%}"
            )
            
            total_flows += flows
            total_anomalies += anomalies_count
        
        # Add totals row
        table.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold]{total_flows:,}[/bold]",
            f"[bold]{total_anomalies}[/bold]",
            f"[bold]{total_anomalies/total_flows:.2%}[/bold]" if total_flows > 0 else "[bold]0.00%[/bold]"
        )
        
        console.print(table)
        
        # Show recent anomalies
        if anomalies:
            console.print("\n[bold]Recent Anomalies:[/bold]")
            for anomaly in anomalies[:5]:  # Show last 5
                console.print(f"  • {anomaly.get('detected_at', 'N/A')}: "
                            f"Flow {anomaly.get('flow_id', 'N/A')} - "
                            f"Severity: {anomaly.get('severity', 'Medium')}")
        
        # Save to file if requested
        if args.output:
            summary_data = {
                'period_days': period_days,
                'summary': summary,
                'total_flows': total_flows,
                'total_anomalies': total_anomalies,
                'recent_anomalies': anomalies[:10]
            }
            
            with open(args.output, 'w') as f:
                json.dump(summary_data, f, indent=2, default=str)
            
            console.print(f"[green]✓ Summary saved to: {args.output}[/green]")
    
    def handle_explain(self, args):
        """Handle detection explanation - works with both core and custom features"""
        if not self.check_permission('generate_explanations'):
            return

        detection_data = None
        self.original_data = None
        self.original_features = None
        self.feature_stats = None
        model_features = None  # Store the features used by the model

        if args.detection_id:
            # Load from database
            detection = self.db.get_detection(args.detection_id, self.auth.current_user['id'])
            if not detection:
                console.print(f"[red]Detection ID {args.detection_id} not found[/red]")
                return
            
            detection_data = detection['results']
            
            # Get model info to know which features were used
            model_id = detection.get('model_id')
            if model_id:
                model_info = self.db.get_model(model_id, self.auth.current_user['id'])
                if model_info:
                    # Check for features_used first
                    if model_info.get('features_used'):
                        features_data = model_info['features_used']
                        if isinstance(features_data, dict):
                            model_features = features_data.get('features_list', [])
                            console.print(f"[cyan]Model was trained with {len(model_features)} features: {model_features}[/cyan]")
                        elif isinstance(features_data, list):
                            model_features = features_data
                    elif model_info.get('features'):
                        model_features = model_info['features']
                        if isinstance(model_features, str):
                            model_features = json.loads(model_features)
                        console.print(f"[cyan]Model features: {model_features}[/cyan]")
            
            # Load original data to get IP addresses and feature values
            original_file = detection.get('input_file')
            if original_file and os.path.exists(original_file):
                try:
                    original_df = pd.read_csv(original_file)
                    self.original_data = original_df  # Full data for IPs
                    
                    # Use model features if available, otherwise fall back to core features
                    if model_features and len(model_features) > 0:
                        # Use the actual features from the model
                        console.print(f"[cyan]Using model's features for explanation: {model_features}[/cyan]")
                        self.original_features = pd.DataFrame()
                        self.feature_mapping = {}
                        missing_features = []
                        
                        for feature in model_features:
                            if feature in original_df.columns:
                                self.original_features[feature] = pd.to_numeric(original_df[feature], errors='coerce')
                                self.feature_mapping[feature] = feature
                                console.print(f"[dim]  ✓ Found '{feature}'[/dim]")
                            else:
                                # Try case-insensitive match
                                matching_col = next((col for col in original_df.columns if col.lower() == feature.lower()), None)
                                if matching_col:
                                    self.original_features[feature] = pd.to_numeric(original_df[matching_col], errors='coerce')
                                    self.feature_mapping[feature] = matching_col
                                    console.print(f"[dim]  ✓ Mapped '{feature}' → '{matching_col}'[/dim]")
                                else:
                                    self.original_features[feature] = 0
                                    missing_features.append(feature)
                        
                        # Only show missing features message if there are actual missing features
                        if missing_features:
                            console.print(f"[dim] ✗ {len(missing_features)} feature(s) not found, using zeros as placeholders[/dim]")
                    else:
                        # Fall back to core features with mapping
                        console.print(f"[cyan]Using core features with mapping for explanation[/cyan]")
                        feature_variations = {
                            'dur': ['dur', 'Flow Duration', ' Flow Duration', 'flow_duration', 'Duration', 'Dur', ' duration', 'Flow Duration'],
                            'spkts': ['spkts', 'Tot Fwd Pkts', ' Total Fwd Packets', 'Total Fwd Packets', 'fwd_pkts', 'Fwd Packets', 'Fwd Pkts'],
                            'dpkts': ['dpkts', 'Tot Bwd Pkts', ' Total Backward Packets', 'Total Bwd Packets', 'bwd_pkts', 'Bwd Packets', 'Bwd Pkts'],
                            'sbytes': ['sbytes', 'TotLen Fwd Pkts', 'Total Length of Fwd Packets', 'fwd_bytes', 'Fwd Bytes'],
                            'dbytes': ['dbytes', 'TotLen Bwd Pkts', ' Total Length of Bwd Packets' ,'Total Length of Bwd Packets', 'bwd_bytes', 'Bwd Bytes'],
                            'rate': ['rate', 'Flow Byts/s', 'Flow Bytes/s', 'flow_bytes_per_sec', 'Bytes/s'],
                            'smean': ['smean', 'Fwd Pkt Len Mean', ' Fwd Packet Length Mean', 'Fwd Packet Length Mean', 'fwd_pkt_len_mean'],
                            'dmean': ['dmean', 'Bwd Pkt Len Mean', ' Bwd Packet Length Mean', 'Bwd Packet Length Mean', 'bwd_pkt_len_mean'],
                            'swin': ['swin', 'Init Fwd Win Byts', 'Init_Win_bytes_forward', 'Init Fwd Window Bytes', 'fwd_win'],
                            'dwin': ['dwin', 'Init Bwd Win Byts', ' Init_Win_bytes_backward', 'Init Bwd Window Bytes', 'bwd_win']
                        }
                        
                        self.feature_mapping = {}
                        self.original_features = pd.DataFrame()
                        found_count = 0
                        missing_features = []
                        
                        for core_feature, variations in feature_variations.items():
                            found = False
                            for var in variations:
                                if var in original_df.columns:
                                    self.feature_mapping[core_feature] = var
                                    self.original_features[core_feature] = pd.to_numeric(original_df[var], errors='coerce')
                                    found = True
                                    found_count += 1
                                    console.print(f"[dim]  ✓ Mapped '{core_feature}' → '{var}'[/dim]")
                                    break
                                elif var.lower() in [col.lower() for col in original_df.columns]:
                                    actual_col = next(col for col in original_df.columns if col.lower() == var.lower())
                                    self.feature_mapping[core_feature] = actual_col
                                    self.original_features[core_feature] = pd.to_numeric(original_df[actual_col], errors='coerce')
                                    found = True
                                    found_count += 1
                                    console.print(f"[dim]  ✓ Mapped '{core_feature}' → '{actual_col}'[/dim]")
                                    break
                            
                            if not found:
                                self.original_features[core_feature] = 0
                                missing_features.append(core_feature)
                        
                        # Show a summary instead of individual messages
                        if missing_features:
                            console.print(f"[dim]  ℹ️ {len(missing_features)} core feature(s) not found (using zeros): {', '.join(missing_features[:5])}{'...' if len(missing_features) > 5 else ''}[/dim]")
                        console.print(f"[dim]  ✓ Found {found_count} out of 10 core features[/dim]")
                    
                    # Fill NaN values
                    self.original_features = self.original_features.fillna(0)
                    
                    # Calculate statistics for each feature
                    self.feature_stats = {}
                    for feature in self.original_features.columns:
                        values = self.original_features[feature].values
                        self.feature_stats[feature] = {
                            'mean': float(np.mean(values)),
                            'std': float(np.std(values)) if float(np.std(values)) > 0 else 1.0,
                            'min': float(np.min(values)),
                            'max': float(np.max(values))
                        }
                    
                    console.print(f"[green]✓ Loaded original data with {len(self.original_features.columns)} features[/green]")
                    
                except Exception as e:
                    console.print(f"[yellow]Warning: Could not load original data: {e}[/yellow]")
                    self.original_data = None
                    self.original_features = None
            else:
                console.print(f"[yellow]Original data file not found: {original_file}[/yellow]")
                self.original_data = None
                self.original_features = None
        
        elif args.input:
            # Load from file
            if not os.path.exists(args.input):
                console.print(f"[red]Input file not found: {args.input}[/red]")
                return
            
            with open(args.input, 'r') as f:
                detection_data = json.load(f)
            self.original_data = None
            self.original_features = None

        else:
            console.print("[red]Please specify either --detection-id or --input[/red]")
            return

        # Generate explanations
        console.print("[cyan]Generating explanations for first 10 detected anomalies...[/cyan]\n")

        if not detection_data or not detection_data.get('anomalies'):
            console.print("[yellow]No anomalies to explain[/yellow]")
            return

        # Sort anomalies by confidence score (highest first)
        anomalies = sorted(detection_data['anomalies'], 
                        key=lambda x: x.get('confidence', 0), 
                        reverse=True)

        for i, anomaly in enumerate(anomalies[:10]):  # Explain first 10
            self.explain_anomaly(anomaly, i+1)

    def explain_anomaly(self, anomaly, index):
        """Explain a single anomaly - works with both core and custom features"""
        
        # Get confidence score
        confidence = anomaly.get('confidence', anomaly.get('confidence_score', 0))
        severity = anomaly.get('severity', self.calculate_severity(confidence))
        
        panel_content = [
            f"[bold]Anomaly #{index}[/bold]",
            f"Confidence Score: {confidence:.2f}",
            f"Severity: {severity}",
        ]
        
        # Try to get IP information from original data if available
        src_ip = None
        dst_ip = None
        
        if hasattr(self, 'original_data') and self.original_data is not None:
            idx = anomaly.get('index')
            if idx is not None and idx < len(self.original_data):
                row = self.original_data.iloc[idx]
                
                # Check for source IP columns (common variations)
                src_ip_cols = ['srcip', 'src_ip', 'source_ip', 'Source IP', 'Src IP', 'src-ip', 
                            'SourceIP', 'SrcIP', 'source address', 'Source Address']
                for col in src_ip_cols:
                    if col in row.index or col.lower() in [c.lower() for c in row.index]:
                        actual_col = next((c for c in row.index if c.lower() == col.lower()), None)
                        if actual_col:
                            src_ip = str(row[actual_col])
                            break
                
                # Check for destination IP columns
                dst_ip_cols = ['dstip', 'dst_ip', 'destination_ip', 'Destination IP', 'Dst IP', 'dst-ip',
                            'DestIP', 'DstIP', 'destination address', 'Destination Address']
                for col in dst_ip_cols:
                    if col in row.index or col.lower() in [c.lower() for c in row.index]:
                        actual_col = next((c for c in row.index if c.lower() == col.lower()), None)
                        if actual_col:
                            dst_ip = str(row[actual_col])
                            break
        
        # Add IP information only if found
        if src_ip:
            panel_content.append(f"Source IP: {src_ip}")
        if dst_ip:
            panel_content.append(f"Destination IP: {dst_ip}")
        
        # Add available feature values
        if 'top_features' in anomaly and anomaly['top_features']:
            panel_content.append("\n[bold]Contributing Features Data:[/bold]")
            features = anomaly['top_features']
            
            # Nice display names for core features
            nice_names = {
                'dur': 'Duration', 'spkts': 'Src Packets', 'dpkts': 'Dst Packets',
                'sbytes': 'Src Bytes', 'dbytes': 'Dst Bytes', 'rate': 'Flow Rate',
                'smean': 'Avg Src Pkt Size', 'dmean': 'Avg Dst Pkt Size',
                'swin': 'Src Window', 'dwin': 'Dst Window'
            }
            
            for feat_name, feat_val in features.items():
                display_name = nice_names.get(feat_name, feat_name)
                if isinstance(feat_val, (int, float)):
                    # Format based on feature type
                    if feat_name in ['sbytes', 'dbytes']:
                        panel_content.append(f"  • {display_name}: {feat_val:,.2f} bytes")
                    elif feat_name in ['dur']:
                        panel_content.append(f"  • {display_name}: {feat_val:.2f} seconds")
                    elif feat_name in ['rate']:
                        panel_content.append(f"  • {display_name}: {feat_val:.2f} bytes/sec")
                    else:
                        panel_content.append(f"  • {display_name}: {feat_val:.2f}")
                else:
                    panel_content.append(f"  • {display_name}: {feat_val}")
        
        # Generate AI decision explanation
        explanation = self.generate_explanation(confidence, severity)
        if explanation:
            panel_content.append(f"\n[bold]AI Decision Explanation:[/bold]")
            panel_content.append(explanation)
        
        console.print(Panel(
            "\n".join(panel_content),
            title=f"Anomaly Explanation",
            border_style="yellow" if severity in ['High', 'Critical'] else "cyan"
        ))

    def generate_explanation(self, confidence, severity):
        """Generate explanation"""
        
        explanation_parts = []
        
        # 1. What was detected
        if severity == "Critical":
            explanation_parts.append("[CRITICAL ALERT] The model detected a highly anomalous traffic pattern that strongly deviates from normal behavior. This requires immediate investigation.")
        elif severity == "High":
            explanation_parts.append("[HIGH SEVERITY] Significant deviation detected in network traffic pattern. Investigate promptly.")
        elif severity == "Medium":
            explanation_parts.append("[MEDIUM SEVERITY] Moderate deviation detected. Review the contributing factors below.")
        elif severity == "Low":
            explanation_parts.append("[LOW SEVERITY] Minor deviation detected. Monitor for any changes.")
        else:
            explanation_parts.append("[MINIMAL] Slight deviation within acceptable range.")
        
        # 2. Confidence level
        if confidence >= 0.9:
            explanation_parts.append(f"High confidence ({confidence:.1%}) - The model is very certain this is anomalous.")
        elif confidence >= 0.7:
            explanation_parts.append(f"Moderate confidence ({confidence:.1%}) - Multiple indicators suggest anomalous behavior.")
        elif confidence >= 0.5:
            explanation_parts.append(f"Low confidence ({confidence:.1%}) - Some deviation detected but pattern is mostly normal.")
        else:
            explanation_parts.append(f"ℹMinimal confidence ({confidence:.1%}) - Mostly normal with slight variations.")
        
        # 3. Explain how confidence score is calculated (NSA + KNN blending)
        explanation_parts.append("\n[bold]How Confidence Score is Calculated:[/bold]")
        explanation_parts.append("The model uses a hybrid RNSA (Real-Valued Negative Selection) + KNN approach with 0.5 threshold" \
        "\nwhere confidence (probability of being abnormal) ranges 0 to 1. It generates detectors and checks their coverage" \
        "\n- if a detector directly covers this region, then RNSA successfully found an anomaly" \
        "\n- if no detector covers the region, KNN helps RNSA determine the final confidence score.")
        
        explanation_parts.append("  • For COVERED samples (detected by RNSA): 70% RNSA detector coverage score + 30% KNN neighbor score")
        explanation_parts.append("  • For HOLE samples (no detector coverage): 30% RNSA detector coverage score + 70% KNN neighbor score")
        
        return "\n".join(explanation_parts)

    def calculate_severity(self, confidence):
        """Calculate severity based on confidence score (0-1 scale)"""
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
    
    def get_important_features(self, row, model):
        """Get important features for explanation with JSON serializable values"""
        features = {}
    
        if hasattr(model, 'feature_names'):
            for feature in model.feature_names:
                if feature in row:
                    value = row[feature]
                    if pd.notna(value):
                        # Convert to float for JSON serialization
                        features[feature] = float(abs(float(value)))
    
        # Normalize to sum to 1
        total = sum(features.values())
        if total > 0:
            features = {k: float(v/total) for k, v in features.items()}
    
        # Return sorted features (converted to regular dict)
        return dict(sorted(features.items(), key=lambda x: x[1], reverse=True)[:5])
    
    def run(self):
        """Main CLI runner"""
        args = self.parser.parse_args()
        self.args = args
        
        try:
            # Handle version flag first
            if args.version:
                self.handle_version(args)
                return
            
            if not args.command:
                self.parser.print_help()
                return
            
            # Map commands to handlers
            command_handlers = {
                'login': self.handle_login,
                'logout': self.handle_logout,
                'uninstall': self.handle_uninstall,
                'reset-pass': self.handle_reset_password,
                'detect': self.handle_detect,
                'train': self.handle_train,
                'summary': self.handle_summary,
                'explain': self.handle_explain,
                'list-models': self.handle_list_models,
                'status': self.handle_status,
                'interactive-gui': self.handle_interactive_gui,
            }
            
            # Admin commands
            if args.command == 'admin' and args.admin_command:
                admin_handlers = {
                    'user-create': self.handle_admin_user_create,
                    'user-modify': self.handle_admin_user_modify,
                    'user-deactivate': self.handle_admin_user_deactivate,
                    'audit-logs': self.handle_admin_audit_logs,
                    'system-report': self.handle_admin_system_report,
                }
                
                if args.admin_command in admin_handlers:
                    admin_handlers[args.admin_command](args)
                else:
                    console.print("[red]Unknown admin command[/red]")
                    return
            elif args.command in command_handlers:
                command_handlers[args.command](args)
            else:
                console.print("[red]Unknown command[/red]")
                self.parser.print_help()
        
        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled by user[/yellow]")
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            if hasattr(self, 'args') and self.args.verbose:
                console.print(traceback.format_exc())
        finally:
            self.db.close()
    
    def handle_list_models(self, args):
        """List available models"""
        if not self.check_auth():
            return
    
        models = self.db.get_user_models(self.auth.current_user['id'])
    
        if not models:
            console.print("[yellow]No models found[/yellow]")
            return
    
        # Get admin view if user is admin
        if self.auth.is_admin():
            all_models = self.db.get_all_models()
            console.print(f"[cyan]Showing {len(models)} of {len(all_models)} total models in system[/cyan]\n")
    
        table = Table(title="Available Models", box=ROUNDED)
        table.add_column("ID", style="cyan", width=6)
        table.add_column("Name", style="green", width=30)
        table.add_column("Type", style="yellow", width=15)
        table.add_column("Accuracy", justify="right", width=10)
        table.add_column("Precision", justify="right", width=10)
        table.add_column("Recall", justify="right", width=10)
        table.add_column("F1", justify="right", width=8)
        table.add_column("Samples", justify="right", width=10)
        table.add_column("Created", style="blue", width=12)
    
        for model in models:
            accuracy = f"{model.get('accuracy', 0):.2%}" if model.get('accuracy') else "N/A"
            precision = f"{model.get('precision', 0):.2%}" if model.get('precision') else "N/A"
            recall = f"{model.get('recall', 0):.2%}" if model.get('recall') else "N/A"
            f1 = f"{model.get('f1_score', 0):.2%}" if model.get('f1_score') else "N/A"
            created = model['created_at'].strftime('%Y-%m-%d')
            samples = f"{model.get('training_samples', 0):,}" if model.get('training_samples') else "N/A"
        
            table.add_row(
                str(model['id']),
                model['name'][:28] + ".." if len(model['name']) > 28 else model['name'],
                model.get('model_type', 'rnsa_knn'),
                accuracy,
                precision,
                recall,
                f1,
                samples,
                created
            )
    
        console.print(table)
    
        # Show detailed view for the first model if requested
        if len(models) == 1:
            model = models[0]
            console.print(f"\n[cyan]Model Details (ID: {model['id']}):[/cyan]")
            console.print(f"  Path: {model['model_path']}")
            if model.get('features_count'):
                console.print(f"  Features: {model['features_count']}")
            if model.get('training_samples'):
                console.print(f"  Training Samples: {model['training_samples']:,}")
    
    def handle_status(self, args):
        """Show system status"""
        if not self.check_auth():
            return
    
        # Get system info
        try:
            system_info = get_system_info()
        except Exception as e:
            console.print(f"[yellow]Warning: Could not get full system info: {e}[/yellow]")
            system_info = {"status": "partial"}
    
        # Get database stats
        db_stats = self.db.get_database_stats()
    
        # Display status
        status_lines = [
            f"[bold]Vigilante Intrusion Detection System[/bold]",
            f"Version: 1.0.0",
            f"User: {self.auth.current_user['username']}",
            f"Role: {self.auth.current_role}",
            f"Session: Active",
            f"Database: Connected",
            f"Models: {db_stats.get('model_count', 0)}",
            f"Detections: {db_stats.get('detection_count', 0)}",
        ]
    
        # Add system info if available
        if system_info and system_info != {"status": "partial"}:
            status_lines.extend([
                f"",
                f"[cyan]System:[/cyan] {system_info.get('system', 'Unknown')} {system_info.get('release', '')}",
                f"Python: {system_info.get('python_version', 'Unknown')}",
                f"CPU: {system_info.get('cpu_count', '?')} cores ({system_info.get('cpu_percent', 0)}% used)",
                f"Memory: {system_info.get('available_memory', '?')} available / {system_info.get('total_memory', '?')} total",
            ])
        
            # Add ML framework info
            if not system_info.get('torch_available', True):
                status_lines.append(f"ML Framework: scikit-learn based (PyTorch not required)")
    
        console.print(Panel.fit(
            "\n".join(status_lines),
            title="System Status",
            border_style="green"
        ))
    
    def handle_password_change_interactive(self, user_id):
        """Handle interactive password change during login"""
        console.print("\n[bold yellow]Password Change Required[/bold yellow]")
        console.print("You must change your password before proceeding.\n")
        
        # Get user info
        user = self.db.get_user_by_id(user_id)
        if not user:
            console.print("[red]User not found[/red]")
            return
        
        # For first login, we can't verify old password since it's a temporary one
        # We'll just set a new password
        while True:
            new_password = getpass("New password: ")
            confirm_password = getpass("Confirm new password: ")
            
            if new_password != confirm_password:
                console.print("[red]Passwords do not match[/red]")
                continue
            
            if len(new_password) < 8:
                console.print("[red]Password must be at least 8 characters[/red]")
                continue
            
            break
        
        # Update password
        password_hash = self.auth.hash_password(new_password)
        try:
            self.db.reset_user_password(user_id, password_hash, must_change=False)
            console.print("[green]✓ Password changed successfully[/green]")
            console.print("[cyan]Please log in again with your new password[/cyan]")
        except Exception as e:
            console.print(f"[red]Failed to change password: {e}[/red]")
    
    def handle_version(self, args):
        """Display version information"""
        console.print("[bold cyan]Vigilante Intrusion Detection System[/bold cyan]")
        console.print("Version: 1.0.0")
        console.print("Model: Real-Valued Negative Selection (RNSA) + K-Nearest Neighbors (KNN)")
        console.print("Database: PostgreSQL (Neon)")
        console.print("Roles: Administrator, Analyst")
        console.print("Author: Vigilante Team")


def main():
    """Main entry point"""
    cli = VigilanteCLI()
    cli.run()

if __name__ == "__main__":
    main()