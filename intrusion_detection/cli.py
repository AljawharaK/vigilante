#!/usr/bin/env python3
"""Main CLI interface for Vigilante Intrusion Detection System"""

import argparse
import sys
import os
import json
import tempfile
from datetime import datetime, timedelta
from getpass import getpass
from typing import Optional
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
  vigilante --login                                      # Interactive login
  vigilante --train --input traffic.csv                  # Train model
  vigilante --detect --input test.csv --model-id 1       # Detect anomalies
  vigilante --admin --user-create --username analyst1    # Create user (admin only)
  vigilante --summary --period 7d                        # Weekly summary
  vigilante --explain --detection-id 1                   # Explain detection
            """
        )
        
        # Main command groups
        subparsers = parser.add_subparsers(dest='command', help='Command')
        
        # Authentication commands
        auth_parser = subparsers.add_parser('login', help='Login to system')
        auth_parser.add_argument('--username', help='Username')
        auth_parser.add_argument('--password', help='Password (not recommended)')
        
        subparsers.add_parser('logout', help='Logout from system')
        
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
        detect_parser.add_argument('--output', help='Output JSON file')
        detect_parser.add_argument('--explain', action='store_true', help='Generate explanations')
        
        # Training commands (available to both Admin and Analyst)
        train_parser = subparsers.add_parser('train', help='Train model')
        train_parser.add_argument('--input', required=True, help='Training data CSV')
        train_parser.add_argument('--threshold', type=float, default=0.8, help='Anomaly threshold')
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
        """Load session from file"""
        if self.session_file.exists():
            try:
                with open(self.session_file, 'r') as f:
                    session_data = json.load(f)
                
                session_token = session_data.get('session_token')
                if session_token and self.auth.validate_session(session_token):
                    console.print(f"[green]✓ Session loaded for {self.auth.current_user['username']}[/green]")
                    return True
            except Exception as e:
                console.print(f"[yellow]Warning: Could not load session: {e}[/yellow]")
        return False
    
    def save_session(self):
        """Save session to file"""
        if self.auth.current_session:
            session_data = {
                'session_token': self.auth.current_session,
                'username': self.auth.current_user['username'],
                'saved_at': datetime.now().isoformat()
            }
            with open(self.session_file, 'w') as f:
                json.dump(session_data, f, indent=2)
    
    def clear_session(self):
        """Clear session file"""
        if self.session_file.exists():
            self.session_file.unlink()
    
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
    def handle_admin_user_create(self, args):
        """Create new user (Administrator only)"""
        if not self.check_admin():
            return
        
        # Use a standard temporary password
        temp_password = "temp123"
    
        # Hash the password for storage
        password_hash = self.auth.hash_password(temp_password)
        
        try:
            # Create user with simplified role
            user_id = self.db.create_user(
                username=args.username,
                password_hash=password_hash,
                email=args.email,
                role=args.role,
                created_by=self.auth.current_user['id']
            )
            
            # Log audit event
            self.db.log_audit_event(
                user_id=self.auth.current_user['id'],
                username=self.auth.current_user['username'],
                action="user_create",
                resource=args.username,
                status="success",
                details={"role": args.role, "email": args.email}
            )
            
            console.print(f"[green]✓ User '{args.username}' created successfully[/green]")
            console.print(f"Temporary password: [yellow]{temp_password}[/yellow]")
            console.print(f"Role: [cyan]{args.role}[/cyan]")
            console.print(f"Email: [cyan]{args.email}[/cyan]")
            console.print(f"Status: [green]Active[/green]")
            console.print("\n[bold yellow]⚠️ User must change password on first login[/bold yellow]")
            
        except Exception as e:
            console.print(f"[red]✗ Failed to create user: {e}[/red]")
    
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
    
        # Display summary stats
        console.print(f"[green]Found {len(logs)} audit log entries[/green]\n")
    
        # Create detailed table
        table = Table(title=f"Audit Logs - Last {args.period}", box=ROUNDED)
        table.add_column("ID", style="dim", width=6)
        table.add_column("Timestamp", style="cyan", width=20)
        table.add_column("User", style="green", width=15)
        table.add_column("Action", style="yellow", width=20)
        table.add_column("Resource", style="blue", width=30)
        table.add_column("Status", style="magenta", width=10)
    
        for log in logs[:100]:  # Show first 100
            timestamp = log['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            username = log['username'] or 'System'
            resource = log['resource'] or '-'
        
            # Truncate long resource names
            if len(resource) > 25:
                resource = resource[:22] + '...'
        
            table.add_row(
                str(log['id']),
                timestamp,
                username,
                log['action'],
                resource,
                log['status']
            )
    
        console.print(table)
        console.print(f"[dim]Showing {min(100, len(logs))} of {len(logs)} logs[/dim]")
    
        # Show action summary
        from collections import Counter
        actions = Counter([log['action'] for log in logs])
    
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
        if not self.check_admin():
            return
    
        period_days = int(args.period.rstrip('d'))
        console.print(f"[cyan]Generating system report for the last {args.period}...[/cyan]")
    
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Collecting data...", total=5)
        
            end_date = datetime.now()
            start_date = end_date - timedelta(days=period_days)
        
            progress.update(task, advance=1, description="Getting detection summary...")
            try:
                detection_summary = self.db.get_detection_summary(None, period_days)
            except Exception as e:
                console.print(f"[yellow]Warning: Could not get detection summary: {e}[/yellow]")
                detection_summary = []
        
            progress.update(task, advance=1, description="Getting user activity...")
            try:
                user_activity = self.db.get_user_activity(period_days)
            except Exception as e:
                console.print(f"[yellow]Warning: Could not get user activity: {e}[/yellow]")
                user_activity = {}
        
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
    
        # Calculate totals
        total_flows = sum(d.get('total_flows', 0) for d in detection_summary)
        total_anomalies = sum(d.get('total_anomalies', 0) for d in detection_summary)
    
        # Display comprehensive summary
        console.print(Panel.fit(
            f"[bold cyan]System Report Summary[/bold cyan]\n"
            f"────────────────────────────\n"
            f"Period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}\n"
            f"Total Flows Analyzed: [green]{total_flows:,}[/green]\n"
            f"Total Anomalies: [yellow]{total_anomalies}[/yellow]\n"
            f"Anomaly Rate: [magenta]{(total_anomalies/total_flows if total_flows>0 else 0):.2%}[/magenta]\n"
            f"Avg False Positive Rate: [cyan]{self.calculate_avg_fpr(detection_summary):.2f}%[/cyan]\n",
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
        
            for det in all_detections[:20]:  # Show first 20
                det_table.add_row(
                    str(det['id']),
                    det.get('username', 'N/A'),
                    det['created_at'].strftime('%Y-%m-%d %H:%M'),
                    f"{det['total_flows']:,}",
                    str(det['anomalies_detected']),
                    str(det.get('model_id', 'N/A'))
                )
            console.print(det_table)
            console.print(f"[dim]Showing {min(20, len(all_detections))} of {len(all_detections)} detections[/dim]")
        else:
            console.print("[yellow]No detection data found for the specified period[/yellow]")
    
        # Display all models
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
                model_table.add_row(
                    str(model['id']),
                    model['name'][:30] + "..." if len(model['name']) > 30 else model['name'],
                    model.get('username', 'N/A'),
                    model.get('model_type', 'rnsa_knn'),
                    f"{model.get('accuracy', 0):.2%}" if model.get('accuracy') else "N/A",
                    f"{model.get('training_samples', 0):,}",
                    model['created_at'].strftime('%Y-%m-%d')
                )
            console.print(model_table)
        else:
            console.print("[yellow]No models found in the system[/yellow]")

        # Display user activity
        if user_activity and any(user_activity.values()):
            activity_table = Table(title="User Activity Summary", box=ROUNDED)
            activity_table.add_column("Metric", style="cyan")
            activity_table.add_column("Count", style="green", justify="right")
        
            activity_table.add_row("Total Logins", str(user_activity.get('total_logins', 0)))
            activity_table.add_row("Models Trained", str(user_activity.get('models_trained', 0)))
            activity_table.add_row("Detection Jobs Run", str(user_activity.get('detection_jobs_run', 0)))
        
            console.print(activity_table)
        else:
            console.print("[yellow]No user activity data found for the specified period[/yellow]")

        # Display recent anomalies
        if recent_anomalies:
            anomaly_table = Table(title="Recent Anomalies", box=ROUNDED)
            anomaly_table.add_column("Detected At", style="cyan")
            anomaly_table.add_column("Flow ID", style="yellow")
            anomaly_table.add_column("Confidence", justify="right")
            anomaly_table.add_column("Severity")
        
            for anomaly in recent_anomalies[:10]:
                anomaly_table.add_row(
                    anomaly.get('detected_at', 'N/A').strftime('%Y-%m-%d %H:%M') if hasattr(anomaly.get('detected_at'), 'strftime') else str(anomaly.get('detected_at', 'N/A')),
                    str(anomaly.get('index', 'N/A')),
                    f"{anomaly.get('confidence', 0):.2f}",
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
                "detection_rate": total_anomalies / total_flows if total_flows > 0 else 0,
                "avg_false_positive_rate": self.calculate_avg_fpr(detection_summary),
            },
            "user_activity": user_activity,
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
                # Fallback to JSON
                json_output = args.output.replace('.pdf', '.json')
                with open(json_output, 'w') as f:
                    json.dump(report_data, f, indent=2, default=str)
                console.print(f"[yellow]JSON report saved to: {json_output}[/yellow]")

    # Detection Commands
    def handle_detect(self, args):
        """Handle anomaly detection with feature alignment"""
    
        if not self.check_permission('run_detection'):
            return

        if not os.path.exists(args.input):
            console.print(f"[red]Input file not found: {args.input}[/red]")
            return
    
        # Load model
        model = None
        if args.model_id:
            # Load from database
            model_data = self.db.get_model(args.model_id, self.auth.current_user['id'])
            if not model_data:
                console.print(f"[red]Model ID {args.model_id} not found[/red]")
                return

            model_path = model_data['model_path']
    
            # Check if path exists
            if not os.path.exists(model_path):
                console.print(f"[red]Model file not found: {model_path}[/red]")
        
                # Try alternative paths
                possible_paths = [
                model_path,
                    os.path.join("saved_models", os.path.basename(model_path)),
                    os.path.basename(model_path),
                    os.path.join("models", os.path.basename(model_path))
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
        console.print(f"[cyan]Model expects {feature_info['features_count']} core features[/cyan]")

        # Perform detection with timing
        import time
        start_time = time.time()
    
        self.db.set_long_timeout()

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
                label_col = None
                label_column_name = None  # Store the actual column name

                # Look for label columns (case-insensitive)
                possible_label_cols = ['label', 'Label', ' Label', 'attack_type', 'class', 'Label.1', 'LABEL', 'attack', 'Attack']
                for col in possible_label_cols:
                    if col in df.columns:
                        has_labels = True
                        label_col = col
                        label_column_name = col  # Store for later use
        
                        # Get original labels first
                        original_labels = df[col].values
        
                        console.print(f"[green]✓ Found label column: '{col}'[/green]")
                        console.print(f"  Original labels: {np.unique(original_labels)}")

                        # Convert string labels to binary (0 for normal/benign, 1 for attack/malicious)
                        if original_labels.dtype == 'object' or isinstance(original_labels[0], str):
                            # Define what counts as normal/benign (case-insensitive)
                            normal_terms = ['benign', 'Benign', 'BENIGN', 'normal', 'Normal', '0', 'false', 'no', 'legitimate']
            
                            y_true_binary = []
                            for val in original_labels:
                                val_str = str(val).lower().strip()
                                # Check if this is a normal/benign label
                                is_normal = False
                                for term in normal_terms:
                                    if term in val_str:
                                        is_normal = True
                                        break
                
                                if is_normal:
                                    y_true_binary.append(0)  # Normal
                                else:
                                    y_true_binary.append(1)  # Attack/Malicious
            
                            y_true = np.array(y_true_binary)
                            console.print(f"  Converted to binary: 0=normal, 1=attack")
                            console.print(f"  Class distribution: Normal={np.sum(y_true==0)}, Attack={np.sum(y_true==1)}")
                        else:
                            # Already numeric, just convert to int
                            y_true = original_labels.astype(np.int32)

                        # Don't drop the label column yet - we need it for preprocessing alignment
                        # We'll use a copy for features but keep original for labels
                        break

                if not has_labels:
                    console.print("[yellow]No label column found. Will perform unsupervised detection only.[/yellow]")
                    df_features = df.copy()
                    y_true = None
                else:
                    # Create features dataframe WITHOUT the label column for preprocessing
                    df_features = df.drop(columns=[label_column_name])
        
                # Show feature analysis
                available_features, feature_mapping = model._find_features_in_data(df_features)
    
                if len(available_features) < 5:  # Less than half of features
                    console.print(f"[yellow]Warning: Only {len(available_features)} of {len(model.CORE_FEATURES)} features found[/yellow]")
                    console.print("[yellow]Missing features will be filled with zeros[/yellow]")

                # Preprocess data (this will automatically align features)
                X = model.preprocess_data(df_features, fit_scaler=False)
    
                # Detect anomalies
                predictions, confidence_scores = model.predict(X)
    
                # Calculate execution time
                execution_time = time.time() - start_time
    
                # Prepare results with metrics
                if has_labels and y_true is not None:
                    # Ensure y_true is numpy array and properly formatted
                    if isinstance(y_true, list):
                        y_true = np.array(y_true)
    
                    # Ensure y_true is binary (0/1)
                    if len(np.unique(y_true)) > 2:
                        console.print(f"[yellow]Warning: Found {len(np.unique(y_true))} unique labels. Converting to binary...[/yellow]")
                        normal_terms = ['benign', 'Benign', 'BENIGN', 'normal', 'Normal', '0', 'false', 'no', 'legitimate']
                        y_true_binary = []
                        for val in y_true:
                            val_str = str(val).lower().strip()
                            if any(term in val_str for term in normal_terms):
                                y_true_binary.append(0)
                            else:
                                y_true_binary.append(1)
                        y_true = np.array(y_true_binary)
    
                    # Ensure predictions are binary
                    predictions = (predictions > 0.5).astype(int) if predictions.dtype != int else predictions
    
                    # Ensure same length
                    if len(y_true) != len(X):
                        console.print(f"[yellow]Warning: Label length ({len(y_true)}) doesn't match features ({len(X)}). Truncating...[/yellow]")
                        min_len = min(len(y_true), len(X))
                        y_true = y_true[:min_len]
                        predictions = predictions[:min_len]
                        confidence_scores = confidence_scores[:min_len]
    
                    # Double-check types
                    console.print(f"[dim]Final types - y_true: {y_true.dtype}, predictions: {predictions.dtype}[/dim]")
                    console.print(f"[dim]Final values - y_true unique: {np.unique(y_true)}, predictions unique: {np.unique(predictions)}[/dim]")
    
                    # Calculate all metrics using ground truth labels
                    results = self.prepare_detection_results_with_labels(
                        df_features, predictions, confidence_scores, y_true, model, execution_time
                    )
                else:
                    # Unlabeled detection - basic results only
                    results = self.prepare_detection_results(
                        df_features, predictions, confidence_scores, model, execution_time
                    )
        
                # Add feature alignment info
                results['feature_alignment'] = {
                    'core_features': model.CORE_FEATURES,
                    'features_found': len(available_features),
                    'feature_mapping': feature_mapping
                }

                # Convert to JSON serializable
                serializable_results = self.make_json_serializable(results)
    
                # Save to database - use a fresh connection for saving
                try:
                    # Create a new database manager instance for saving results
                    # This ensures we have a fresh connection
                    save_db = DatabaseManager()
    
                    detection_id = save_db.save_detection(
                        user_id=self.auth.current_user['id'],
                        model_id=args.model_id if args.model_id else None,
                        input_file=args.input,
                        results=serializable_results
                    )
    
                    # Close the temporary connection
                    save_db.close()
    
                except Exception as e:
                    console.print(f"[yellow]Warning: Could not save detection to database: {e}[/yellow]")
                    detection_id = None
    
                progress.update(task, completed=100)
        
        except Exception as e:
            console.print(f"[red]Detection failed: {e}[/red]")
            if hasattr(self.args, 'verbose') and self.args.verbose:
                console.print(traceback.format_exc())
            return

        # Display results
        console.print(f"[green]✓ Detection analysis completed[/green]")
        console.print(f"[yellow]⚠️ Anomalies detected: {results['anomalies_detected']}[/yellow]")

        # Show summary table
        self.display_detection_summary(results)

        # Show feature alignment info
        if 'feature_alignment' in results:
            alignment = results['feature_alignment']
            console.print(f"\n[cyan]Feature Alignment:[/cyan]")
            console.print(f"  Core features: {len(alignment['core_features'])}")
            console.print(f"  Features found: {alignment['features_found']}")
            if alignment.get('feature_mapping'):
                console.print(f"  Mapped {len(alignment['feature_mapping'])} features")

        # Show anomalies if any
        if results['anomalies_detected'] > 0:
            console.print("\n[bold]Detected Anomalies:[/bold]")
            for anomaly in results['anomalies'][:10]:  # Show first 10
                console.print(f"  Flow {anomaly.get('index', 'N/A')} - "
                            f"Confidence: {anomaly.get('confidence', 0):.2f} - "
                            f"Severity: {anomaly.get('severity', 'Medium')}")

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
        console.print(f"\n[yellow]For full explanations, use:[/yellow]")
        console.print(f"[cyan]  vigilante explain --detection-id {detection_id}[/cyan]")

    def prepare_detection_results(self, df, predictions, confidence_scores, model, execution_time=None):
        """Prepare detection results in structured format with JSON serializable types"""
        anomalies = []
        anomaly_indices = np.where(predictions == 1)[0]
    
        # Calculate mean reconstruction error (using inverse of confidence as proxy)
        # For RNSA+KNN, lower confidence = higher "reconstruction error" (more anomalous)
        reconstruction_errors = 1.0 - confidence_scores
        mean_reconstruction_error = float(np.mean(reconstruction_errors))

        for idx in anomaly_indices:
            confidence = float(confidence_scores[idx]) if idx < len(confidence_scores) else 0.5
            reconstruction_error = float(reconstruction_errors[idx]) if idx < len(reconstruction_errors) else 0.5
        
            anomaly = {
                'index': int(idx),
                'confidence': confidence,
                'reconstruction_error': reconstruction_error,
                'severity': self.calculate_severity(confidence),
            }
        
            # Add some feature values for context (limit to first few to avoid huge results)
            if idx < len(df):
                row = df.iloc[idx]
                top_features = {}
                feature_names = model.feature_names if model.feature_names else []
            
                for i, feat in enumerate(feature_names[:5]):  # First 5 features
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
    
        # Calculate detection rate (True Positive Rate) - Note: We don't have ground truth labels here
        # For detection results without labels, we can only report the raw detection rate
        # The formula e = TP / (TP + FP) requires actual labels to calculate
        detection_rate = float(anomalies_detected / total_flows) if total_flows > 0 else 0.0

        result = {
            'total_flows': total_flows,
            'anomalies_detected': anomalies_detected,
            'detection_rate': detection_rate,  # Add explicit detection_rate field
            'mean_reconstruction_error': mean_reconstruction_error,
            'anomalies': anomalies[:100],  # Limit to first 100 for performance
            'mean_confidence': float(np.mean(confidence_scores)) if len(confidence_scores) > 0 else 0,
            'metrics': model.metrics if hasattr(model, 'metrics') else {}
        }

        # Add execution time if provided
        if execution_time is not None:
            result['execution_time'] = self.format_execution_time(execution_time)
            result['execution_time_seconds'] = float(execution_time)

        return result

    def prepare_detection_results_with_labels(self, df, predictions, confidence_scores, y_true, model, execution_time=None):
        """Prepare detection results with full metrics using ground truth labels"""
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
                normal_terms = ['benign', 'normal', 'legitimate', '0']
                y_true_binary = []
                for val in y_true:
                    val_str = str(val).lower().strip()
                    if any(term in val_str for term in normal_terms):
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
    
        # Calculate reconstruction errors (proxy)
        reconstruction_errors = 1.0 - confidence_scores
        mean_reconstruction_error = float(np.mean(reconstruction_errors))

        for idx in anomaly_indices:
            confidence = float(confidence_scores[idx]) if idx < len(confidence_scores) else 0.5
            reconstruction_error = float(reconstruction_errors[idx]) if idx < len(reconstruction_errors) else 0.5
    
            anomaly = {
                'index': int(idx),
                'confidence': confidence,
                'reconstruction_error': reconstruction_error,
                'severity': self.calculate_severity(confidence),
            }
    
            # Add some feature values for context
            if idx < len(df):
                row = df.iloc[idx] if hasattr(df, 'iloc') else df[idx]
                top_features = {}
                feature_names = model.feature_names if model.feature_names else []
        
                for i, feat in enumerate(feature_names[:5]):
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
            'mean_reconstruction_error': mean_reconstruction_error,
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
        youden_j = tpr - fpr
        optimal_idx = np.argmax(youden_j)
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

    # Update display_detection_summary to show all metrics:

    def display_detection_summary(self, results):
        """Display detection summary table with all available metrics"""
        table = Table(title="Detection Summary", box=ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green", justify="right")
    
        table.add_row("Total Flows Analyzed", f"{results['total_flows']:,}")
        table.add_row("Anomalies Detected", str(results['anomalies_detected']))
    
        # Show classification metrics if available
        if 'accuracy' in results and results['accuracy'] > 0:
            table.add_row("Accuracy", f"{results['accuracy']:.2%}")
            table.add_row("Precision (TP/(TP+FP))", f"{results['precision']:.2%}")
            table.add_row("Recall (Detection Rate)", f"{results['recall']:.2%}")
            table.add_row("F1 Score", f"{results['f1_score']:.2%}")
            table.add_row("Detection Rate", f"{results['detection_rate']:.2%}")
            table.add_row("False Positive Rate", f"{results['false_positive_rate']:.2%}")
    
        # Show confusion matrix if available
        if 'true_positives' in results:
            table.add_row("True Positives", str(results['true_positives']))
            table.add_row("False Positives", str(results['false_positives']))
            table.add_row("True Negatives", str(results['true_negatives']))
            table.add_row("False Negatives", str(results['false_negatives']))
    
        table.add_row("Mean Reconstruction Error", f"{results.get('mean_reconstruction_error', 0):.6f}")
        table.add_row("Mean Confidence", f"{results.get('mean_confidence', 0):.6f}")
    
        if 'execution_time' in results:
            table.add_row("Execution Time", results['execution_time'])
    
        console.print(table)

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
    
    # Training Command
    def handle_train(self, args):
        """Handle model training with feature alignment"""
        if not self.check_permission('train_models'):
            return

        if not os.path.exists(args.input):
            console.print(f"[red]Input file not found: {args.input}[/red]")
            return

        # Process features (optional, model will use core features)
        features = None
        if args.features:
            features = [f.strip() for f in args.features.split(',')]

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
                temp_model = IntrusionDetectionModel()
                available_features, feature_mapping = temp_model._find_features_in_data(df_preview)
            
                console.print(f"\n[cyan]Feature Analysis:[/cyan]")
                console.print(f"  Core features required: {len(temp_model.CORE_FEATURES)}")
                console.print(f"  Features found: {len(available_features)}")
                if feature_mapping:
                    console.print(f"  Feature mapping:")
                    for k, v in list(feature_mapping.items())[:5]:
                        console.print(f"    {k} → {v}")
            
                # Train model
                result = self.trainer.train_model(
                    data_path=args.input,
                    model_name=args.model_name or f"model_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    r_s=0.01,
                    max_detectors=1000,
                    k=1,
                    dataset_name=os.path.basename(args.input)
                )
            
                # Create a fresh database connection for saving the model
                # This ensures we don't use a stale connection from long training
                fresh_db = DatabaseManager()
            
                # Save model to database using fresh connection
                model_id = fresh_db.save_model(
                    user_id=self.auth.current_user['id'],
                    model_name=result['model_name'],
                    model_path=result['model_path'],
                    dataset_name=os.path.basename(args.input),
                    metrics=result['metrics'],
                    features=result.get('feature_analysis', {}).get('available_features', features),
                    parameters={
                        'model_type': 'rnsa_knn',
                        'r_s': 0.01,
                        'max_detectors': 1000,
                        'k': 1,
                        'core_features': temp_model.CORE_FEATURES
                    }
                )
            
                # Close the fresh connection
                fresh_db.close()
            
                progress.update(task, completed=100)

            except Exception as e:
                console.print(f"[red]Training failed: {e}[/red]")
                if hasattr(self.args, 'verbose') and self.args.verbose:
                    console.print(traceback.format_exc())
                return

        console.print(f"[green]✓ RNSA+KNN Model trained successfully[/green]")
        console.print(f"Model ID: [cyan]{model_id}[/cyan]")
        console.print(f"Model saved to: [cyan]{result['model_path']}[/cyan]")

        # Show metrics
        self.display_training_metrics(result['metrics'])

        # Show feature summary
        if 'feature_analysis' in result:
            fa = result['feature_analysis']
            console.print(f"\n[cyan]Feature Summary:[/cyan]")
            console.print(f"  Features used: {fa.get('coverage', 0):.1f}% coverage")
            console.print(f"  Features found: {len(fa.get('available_features', []))}")
            console.print(f"  Missing features: {len(fa.get('missing_features', []))}")

        # Log training event
        self.db.log_audit_event(
            user_id=self.auth.current_user['id'],
            username=self.auth.current_user['username'],
            action="model_train",
            resource=args.input,
            status="success",
            details={"model_id": model_id, "model_name": result['model_name']}
        )

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
    
    # Explain Command
    def handle_explain(self, args):
        """Handle detection explanation"""
        if not self.check_permission('generate_explanations'):
            return

        detection_data = None
        self.original_data = None
        self.original_features = None
        self.feature_stats = None

        if args.detection_id:
            # Load from database
            detection = self.db.get_detection(args.detection_id, self.auth.current_user['id'])
            if not detection:
                console.print(f"[red]Detection ID {args.detection_id} not found[/red]")
                return
        
            detection_data = detection['results']
        
            # Load original data to get IP addresses and feature values
            original_file = detection.get('input_file')
            if original_file and os.path.exists(original_file):
                try:
                    original_df = pd.read_csv(original_file)
                    self.original_data = original_df  # Full data for IPs
                
                    # Define all possible feature names for the 10 core features
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
                
                    # For each core feature, try to find a match in the data
                    for core_feature, variations in feature_variations.items():
                        found = False
                        for var in variations:
                            # Check exact match
                            if var in original_df.columns:
                                self.feature_mapping[core_feature] = var
                                self.original_features[core_feature] = pd.to_numeric(original_df[var], errors='coerce')
                                found = True
                                console.print(f"[dim]  ✓ Mapped '{core_feature}' → '{var}'[/dim]")
                                break
                            # Check case-insensitive match
                            elif var.lower() in [col.lower() for col in original_df.columns]:
                                actual_col = next(col for col in original_df.columns if col.lower() == var.lower())
                                self.feature_mapping[core_feature] = actual_col
                                self.original_features[core_feature] = pd.to_numeric(original_df[actual_col], errors='coerce')
                                found = True
                                console.print(f"[dim]  ✓ Mapped '{core_feature}' → '{actual_col}'[/dim]")
                                break
                    
                        if not found:
                            # Feature not found, fill with zeros
                            self.original_features[core_feature] = 0
                            console.print(f"[dim]  ✗ '{core_feature}' not found, using zeros[/dim]")
                
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
                
                    console.print(f"[green]✓ Loaded original data with {len(self.original_features.columns)} core features[/green]")
                    if self.feature_mapping:
                        console.print(f"[green]✓ Found IP columns in data[/green]")
                
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
        console.print("[cyan]Generating explanations for detected anomalies...[/cyan]\n")

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
        """Explain a single anomaly with contributing features from core features"""
    
        # Get confidence score
        confidence = anomaly.get('confidence', anomaly.get('confidence_score', 0))
        if confidence == 0 and 'reconstruction_error' in anomaly:
            # Convert reconstruction error to confidence (inverse)
            confidence = 1.0 - anomaly.get('reconstruction_error', 0)
    
        severity = anomaly.get('severity', self.calculate_severity(confidence))
    
        panel_content = [
            f"[bold]Anomaly #{index}[/bold]",
        ]
    
        # Try to get IP information from original data if available
        src_ip = None
        dst_ip = None
        flow_id = None
    
        if hasattr(self, 'original_data') and self.original_data is not None:
            idx = anomaly.get('index')
            if idx is not None and idx < len(self.original_data):
                row = self.original_data.iloc[idx]
            
                # Check for source IP columns (common variations)
                src_ip_cols = ['srcip', 'src_ip', 'source_ip', 'Source IP', 'Src IP', 'src-ip', 
                              'SourceIP', 'SrcIP', 'source address', 'Source Address']
                for col in src_ip_cols:
                    if col in row.index or col.lower() in [c.lower() for c in row.index]:
                        # Find the actual column name
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
    
        # Add confidence and severity
        panel_content.extend([
            f"Confidence Score: {confidence:.2f}",
            f"Severity: {severity}",
            f"Reconstruction Error: {anomaly.get('reconstruction_error', 0):.6f}"
        ])
    
        # Get feature values for this anomaly
        feature_values = {}
        idx = anomaly.get('index')
    
        if hasattr(self, 'original_features') and self.original_features is not None and idx is not None:
            if idx < len(self.original_features):
                row = self.original_features.iloc[idx]
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
            
                # For each core feature, try to find a match in the row
                for core_feature, variations in feature_variations.items():
                    for var in variations:
                        if var in row.index:
                            feature_values[core_feature] = row[var]
                            break
    
        # Calculate z-scores to find which features are most anomalous
        z_scores = {}
        if feature_values and hasattr(self, 'feature_stats'):
            for feature, value in feature_values.items():
                if feature in self.feature_stats:
                    mean = self.feature_stats[feature]['mean']
                    std = self.feature_stats[feature]['std']
                    if std > 0:
                        z_score = abs((value - mean) / std)
                        z_scores[feature] = z_score
    
        # Show contributing features
        if z_scores:
            # Sort features by how anomalous they are (highest z-score first)
            sorted_features = sorted(z_scores.items(), key=lambda x: x[1], reverse=True)
        
            panel_content.append("\n[bold]Contributing Features (most anomalous first):[/bold]")
            for feature, z_score in sorted_features[:5]:  # Show top 5
                value = feature_values[feature]
                mean = self.feature_stats[feature]['mean']
            
                # Determine deviation direction
                if value > mean:
                    direction = "↑ higher"
                else:
                    direction = "↓ lower"
            
                # Better description of feature names
                feature_names = {
                    'dur': 'Duration',
                    'spkts': 'Src Packets',
                    'dpkts': 'Dst Packets',
                    'sbytes': 'Src Bytes',
                    'dbytes': 'Dst Bytes',
                    'rate': 'Flow Rate',
                    'smean': 'Avg Src Pkt Size',
                    'dmean': 'Avg Dst Pkt Size',
                    'swin': 'Src Window',
                    'dwin': 'Dst Window'
                }
            
                display_name = feature_names.get(feature, feature)
            
                # Format based on z-score magnitude
                if z_score > 3:
                    marker = "🔴"  # Critical
                elif z_score > 2:
                    marker = "🟠"  # High
                elif z_score > 1:
                    marker = "🟡"  # Medium
                else:
                    marker = "🔵"  # Low
            
                panel_content.append(f"  {marker} {display_name}: {value:.2f} ({direction}, {z_score:.1f}σ)")
    
        # Add feature importance if available from model
        elif 'top_features' in anomaly and anomaly['top_features']:
            panel_content.append("\n[bold]Model's Top Contributing Features:[/bold]")
            features = anomaly['top_features']
            sorted_features = sorted(features.items(), 
                                   key=lambda x: abs(x[1] if isinstance(x[1], (int, float)) else 0), 
                                   reverse=True)[:5]
            for feature, value in sorted_features:
                panel_content.append(f"  • {feature}: {value:.4f}")
    
        # Generate AI decision explanation
        explanation = self.generate_ai_explanation(anomaly, confidence, severity, feature_values, z_scores if z_scores else {})
        if explanation:
            panel_content.append(f"\n[bold]AI Decision Explanation:[/bold]")
            panel_content.append(explanation)
    
        console.print(Panel(
            "\n".join(panel_content),
            title=f"Anomaly Explanation",
            border_style="yellow" if severity in ['High', 'Critical'] else "cyan"
        ))
    
    def generate_ai_explanation(self, anomaly, confidence, severity, feature_values=None, z_scores=None):
        """Generate detailed AI explanation for the detection like other security apps"""
    
        explanation_parts = []
    
        # 1. What was detected (like other SIEM tools)
        if severity == "Critical":
            explanation_parts.append("⚠️ CRITICAL ALERT: The model detected a highly anomalous traffic pattern that strongly deviates from normal behavior. This requires immediate investigation.")
        elif severity == "High":
            explanation_parts.append("🔴 HIGH SEVERITY: Significant deviation detected in network traffic pattern. Investigate promptly.")
        elif severity == "Medium":
            explanation_parts.append("🟠 MEDIUM SEVERITY: Moderate deviation detected. Review the contributing factors below.")
        elif severity == "Low":
            explanation_parts.append("🟡 LOW SEVERITY: Minor deviation detected. Monitor for any changes.")
        else:
            explanation_parts.append("🔵 MINIMAL: Slight deviation within acceptable range.")
    
        # 2. Confidence level (like other ML-based detectors)
        if confidence >= 0.9:
            explanation_parts.append(f"✅ High confidence ({confidence:.1%}) - The model is very certain this is anomalous.")
        elif confidence >= 0.7:
            explanation_parts.append(f"📊 Moderate confidence ({confidence:.1%}) - Multiple indicators suggest anomalous behavior.")
        elif confidence >= 0.5:
            explanation_parts.append(f"📉 Low confidence ({confidence:.1%}) - Some deviation detected but pattern is mostly normal.")
        else:
            explanation_parts.append(f"ℹ️ Minimal confidence ({confidence:.1%}) - Mostly normal with slight variations.")
    
        # 3. Feature analysis - what made this anomalous (like feature importance in ML)
        if feature_values and z_scores:
            # Find top 3 most anomalous features
            top_features = sorted(z_scores.items(), key=lambda x: x[1], reverse=True)[:3]
        
            if top_features:
                explanation_parts.append("\n🔍 Primary Indicators (features deviating most from normal):")
            
                for feature, z_score in top_features:
                    value = feature_values.get(feature, 0)
                
                    # Map technical feature names to human-readable descriptions
                    feature_descriptions = {
                        'dur': 'Flow Duration',
                        'spkts': 'Source Packets',
                        'dpkts': 'Destination Packets',
                        'sbytes': 'Source Bytes',
                        'dbytes': 'Destination Bytes',
                        'rate': 'Flow Rate',
                        'smean': 'Average Source Packet Size',
                        'dmean': 'Average Destination Packet Size',
                        'swin': 'Source TCP Window Size',
                        'dwin': 'Destination TCP Window Size'
                    }
                
                    readable_name = feature_descriptions.get(feature, feature)
                
                    # Determine severity of deviation
                    if z_score > 3:
                        deviation = "EXTREME"
                        severity_symbol = "🔴"
                    elif z_score > 2:
                        deviation = "HIGH"
                        severity_symbol = "🟠"
                    elif z_score > 1:
                        deviation = "MODERATE"
                        severity_symbol = "🟡"
                    else:
                        deviation = "LOW"
                        severity_symbol = "🔵"
                
                    # Add context about the value based on feature type
                    if feature in ['dur', 'rate']:
                        if value > 1000:
                            context = f"(unusually high: {value:.2f})"
                        elif value < 0.1:
                            context = f"(unusually low: {value:.2f})"
                        else:
                            context = f"(value: {value:.2f})"
                    elif feature in ['sbytes', 'dbytes']:
                        if value > 10000:
                            context = f"(large data transfer: {value:.2f} bytes)"
                        elif value > 1000:
                            context = f"(medium transfer: {value:.2f} bytes)"
                        else:
                            context = f"(value: {value:.2f} bytes)"
                    else:
                        context = f"(value: {value:.2f})"
                
                    explanation_parts.append(f"  {severity_symbol} {readable_name}: {deviation} deviation {context}")
    
        # 4. Attack type inference based on feature patterns
        if feature_values:
            attack_hints = []
        
            # Check for DoS/DDoS patterns (high rate, many packets)
            if feature_values.get('rate', 0) > 10000:
                attack_hints.append("Extremely high flow rate (>10K) - Possible DoS/DDoS attack")
            elif feature_values.get('rate', 0) > 1000:
                attack_hints.append("High flow rate - May indicate network scanning or DoS")
        
            if feature_values.get('spkts', 0) > 1000:
                attack_hints.append("High source packet count - Possible flooding")
        
            # Check for data exfiltration (large outbound data)
            if feature_values.get('sbytes', 0) > 100000:
                attack_hints.append("Very large outbound data transfer - Possible data exfiltration")
            elif feature_values.get('sbytes', 0) > 10000:
                attack_hints.append("Large outbound data - Investigate for data theft")
        
            # Check for unusual packet sizes
            smean = feature_values.get('smean', 0)
            dmean = feature_values.get('dmean', 0)
            if smean > 1400 and dmean < 100:
                attack_hints.append("Large source packets but small destination packets - Possible command & control traffic")
            elif smean < 100 and dmean > 1400:
                attack_hints.append("Small source packets but large destination packets - Possible data download")
        
            # Check for port scanning indicators (zero window sizes)
            if feature_values.get('dwin', 0) == 0 and feature_values.get('swin', 0) == 0:
                attack_hints.append("Zero TCP window sizes - May indicate port scanning activity")
        
            # Check for unusual duration
            if feature_values.get('dur', 0) > 300:
                attack_hints.append("Very long flow duration (>5 min) - Possible persistent connection")
        
            if attack_hints:
                explanation_parts.append("\n💡 Possible Attack Indicators:")
                for hint in attack_hints[:3]:  # Limit to 3 hints
                    explanation_parts.append(f"  • {hint}")
    
        # 5. Context about the anomaly
        if 'reconstruction_error' in anomaly:
            rec_error = anomaly.get('reconstruction_error', 0)
            if rec_error > 0.9:
                explanation_parts.append(f"\n📊 Model Analysis: Very high reconstruction error ({rec_error:.2f}) - Pattern completely different from normal")
            elif rec_error > 0.7:
                explanation_parts.append(f"\n📊 Model Analysis: High reconstruction error ({rec_error:.2f}) - Significant deviation from normal patterns")
            elif rec_error > 0.5:
                explanation_parts.append(f"\n📊 Model Analysis: Moderate reconstruction error ({rec_error:.2f}) - Partial deviation from normal")
    
        # 6. Recommended action (like other security tools)
        explanation_parts.append("\n📋 Recommended Action:")
        if severity in ['Critical', 'High']:
            explanation_parts.append("  • 🚨 IMMEDIATE ACTION REQUIRED")
            explanation_parts.append("  • Isolate affected host from network")
            explanation_parts.append("  • Capture full packet capture for forensics")
            explanation_parts.append("  • Review firewall and IDS logs for related events")
            explanation_parts.append("  • Escalate to security operations team")
        elif severity == 'Medium':
            explanation_parts.append("  • Monitor the connection for 10-15 minutes")
            explanation_parts.append("  • Check if pattern repeats with same source/destination")
            explanation_parts.append("  • Review recent alerts for related activity")
            explanation_parts.append("  • Update firewall rules if pattern persists")
        else:
            explanation_parts.append("  • Log for baseline reference")
            explanation_parts.append("  • No immediate action required")
            explanation_parts.append("  • Monitor for pattern frequency")
    
        return "\n".join(explanation_parts)

    # Utility Methods
    def calculate_avg_fpr(self, detection_summary):
        """Calculate average false positive rate"""
        if not detection_summary:
            return 0.0
        
        fpr_sum = sum(d.get('avg_false_positive_rate', 0) for d in detection_summary)
        return fpr_sum / len(detection_summary) if detection_summary else 0.0
    
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
        console.print("Model: Deterministic DCA + Denoising Autoencoder")
        console.print("Database: PostgreSQL (Neon)")
        console.print("Roles: Administrator, Analyst")
        console.print("Author: Vigilante Team")


def main():
    """Main entry point"""
    cli = VigilanteCLI()
    cli.run()

if __name__ == "__main__":
    main()