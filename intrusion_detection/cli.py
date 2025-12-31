#!/usr/bin/env python3
"""Main CLI interface for Intrusion Detection System"""

import argparse
import sys
import os
from getpass import getpass
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
import json
import traceback

from .database import DatabaseManager
from .auth import AuthManager
from .model_trainer import ModelTrainer
from .model import IntrusionDetectionModel

console = Console()

class IntrusionDetectionCLI:
    """Main CLI class for intrusion detection system"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.auth = AuthManager(self.db)
        self.trainer = ModelTrainer()
        self.current_model = None
        
        # Load session from environment or file
        self.load_session()
        self.setup_argparse()
    
    def load_session(self):
        """Load session from environment variable or file"""
        import os
        session_file = os.path.join(os.path.expanduser("~"), ".ids_session")
        
        if os.path.exists(session_file):
            try:
                with open(session_file, 'r') as f:
                    session_token = f.read().strip()
                    
                if session_token and self.auth.validate_session(session_token):
                    print(f"📝 Session loaded for user: {self.auth.current_user['username']}")
                    return True
            except:
                pass
        return False
    
    def save_session(self):
        """Save session to file"""
        import os
        if self.auth.current_session:
            session_file = os.path.join(os.path.expanduser("~"), ".ids_session")
            with open(session_file, 'w') as f:
                f.write(self.auth.current_session)
    
    def setup_argparse(self):
        """Setup argument parser"""
        self.parser = argparse.ArgumentParser(
            description='Intrusion Detection System CLI - DCA + Denoising Autoencoder',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s register --username admin --password secure123
  %(prog)s login --username admin --password secure123
  %(prog)s train --data-file data.csv --model-name my-model
  %(prog)s detect --model-path saved_models/my-model --data-file test.csv
  %(prog)s evaluate --model-path saved_models/my-model --test-data test.csv
            """
        )
        
        # Authentication commands
        auth_group = self.parser.add_argument_group('Authentication')
        auth_group.add_argument('--register', action='store_true', help='Register new user')
        auth_group.add_argument('--login', action='store_true', help='Login user')
        auth_group.add_argument('--logout', action='store_true', help='Logout user')
        auth_group.add_argument('--username', type=str, help='Username')
        auth_group.add_argument('--password', type=str, help='Password')
        auth_group.add_argument('--email', type=str, help='Email (for registration)')
        
        # Model management commands
        model_group = self.parser.add_argument_group('Model Management')
        model_group.add_argument('--train', action='store_true', help='Train new model')
        model_group.add_argument('--detect', action='store_true', help='Detect anomalies')
        model_group.add_argument('--evaluate', action='store_true', help='Evaluate model')
        model_group.add_argument('--list-models', action='store_true', help='List all models')
        model_group.add_argument('--model-info', type=str, help='Get model details by path')
        model_group.add_argument('--delete-model', type=str, help='Delete model by path')
        
        # Data arguments
        data_group = self.parser.add_argument_group('Data')
        data_group.add_argument('--data-file', type=str, help='Path to data file')
        data_group.add_argument('--test-data', type=str, help='Path to test data file')
        data_group.add_argument('--model-name', type=str, help='Name for the model')
        data_group.add_argument('--model-path', type=str, help='Path to saved model')
        data_group.add_argument('--output', type=str, help='Output file for results')
        
        # Training parameters
        train_group = self.parser.add_argument_group('Training Parameters')
        train_group.add_argument('--epochs', type=int, default=50, help='Number of training epochs')
        train_group.add_argument('--learning-rate', type=float, default=1e-3, help='Learning rate')
        
        # Other arguments
        self.parser.add_argument('--version', action='store_true', help='Show version')
        self.parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
        self.parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    
    def check_auth(self):
        """Check if user is authenticated"""
        if not self.auth.is_authenticated():
            console.print("[red]Error: You must be logged in to perform this action[/red]")
            console.print("Use [cyan]ids-cli --login --username USER --password PASS[/cyan]")
            return False
        return True
    
    def handle_register(self, args):
        """Handle user registration"""
        if not args.username:
            args.username = input("Username: ")
        if not args.password:
            args.password = getpass("Password: ")
        if not args.email and args.interactive:
            args.email = input("Email (optional): ")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description="Registering...", total=None)
            result = self.auth.register(args.username, args.password, args.email)
        
        if result['success']:
            console.print(f"[green]✓ User {args.username} registered successfully[/green]")
            console.print(f"User ID: [cyan]{result['user_id']}[/cyan]")
        else:
            console.print(f"[red]✗ {result['message']}[/red]")
    
    def handle_login(self, args):
        """Handle user login"""
        if not args.username:
            args.username = input("Username: ")
        if not args.password:
            args.password = getpass("Password: ")
    
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description="Logging in...", total=None)
            result = self.auth.login(args.username, args.password)
    
        if result['success']:
            console.print(f"[green]✓ Login successful! Welcome {args.username}[/green]")
            console.print(f"User ID: [cyan]{result['user_id']}[/cyan]")
        
            # Save session for future use
            self.save_session()
        else:
            console.print(f"[red]✗ {result['message']}[/red]")
    def handle_logout(self, args):
        """Handle user logout"""
        if self.auth.current_session:
            self.auth.logout(self.auth.current_session)
        
            # Remove session file
            import os
            session_file = os.path.join(os.path.expanduser("~"), ".ids_session")
            if os.path.exists(session_file):
                os.remove(session_file)
            
            console.print("[green]✓ Logged out successfully[/green]")
        else:
            console.print("[yellow]You are not logged in[/yellow]")

    def handle_train(self, args):
        """Handle model training"""
        if not self.check_auth():
            return
        
        if not args.data_file:
            console.print("[red]Error: --data-file is required for training[/red]")
            return
        
        if not args.model_name:
            args.model_name = input("Model name: ")
        
        if not os.path.exists(args.data_file):
            console.print(f"[red]Error: Data file not found: {args.data_file}[/red]")
            return
        
        try:
            with Progress() as progress:
                task = progress.add_task("[cyan]Training model...", total=100)
                
                # Train model
                result = self.trainer.train_model(
                    data_path=args.data_file,
                    model_name=args.model_name,
                    epochs=args.epochs,
                    learning_rate=args.learning_rate
                )
                
                # Save to database
                user = self.auth.get_current_user()
                model_id = self.db.save_model(
                    user_id=user['id'],
                    model_name=args.model_name,
                    model_path=result['model_path'],
                    metrics=result['metrics'],
                    parameters={
                        'epochs': args.epochs,
                        'learning_rate': args.learning_rate,
                        'data_file': args.data_file
                    }
                )
                
                progress.update(task, completed=100)
            
            # Display results
            console.print(f"[green]✓ Model trained successfully![/green]")
            console.print(f"Model ID: [cyan]{model_id}[/cyan]")
            console.print(f"Model saved to: [cyan]{result['model_path']}[/cyan]")
            
            # Show metrics
            table = Table(title="Training Results")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            
            metrics = result['metrics']
            table.add_row("Accuracy", f"{metrics.get('accuracy', 'N/A')}")
            table.add_row("Training Loss", f"{metrics.get('final_loss', 'N/A'):.6f}")
            table.add_row("Training Samples", str(result['training_samples']))
            table.add_row("Features", str(result['features_count']))
            table.add_row("Threshold", f"{metrics.get('threshold', 'N/A'):.6f}")
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error during training: {str(e)}[/red]")
            if args.verbose:
                console.print(traceback.format_exc())
    
    def handle_detect(self, args):
        """Handle anomaly detection"""
        if not self.check_auth():
            return
        
        if not args.model_path:
            console.print("[red]Error: --model-path is required for detection[/red]")
            return
        
        if not args.data_file:
            console.print("[red]Error: --data-file is required for detection[/red]")
            return
        
        if not os.path.exists(args.data_file):
            console.print(f"[red]Error: Data file not found: {args.data_file}[/red]")
            return
        
        if not os.path.exists(args.model_path):
            console.print(f"[red]Error: Model path not found: {args.model_path}[/red]")
            return
        
        try:
            with Progress() as progress:
                task = progress.add_task("[cyan]Detecting anomalies...", total=100)
                
                # Detect anomalies
                results = self.trainer.detect_anomalies(args.model_path, args.data_file)
                
                # Save detection history
                user = self.auth.get_current_user()
                
                # Get model ID from database
                model_info = self.db.get_model_by_path(args.model_path, user['id'])
                if model_info:
                    history_id = self.db.save_detection(
                        user_id=user['id'],
                        model_id=model_info['id'],
                        input_file=args.data_file,
                        results=results
                    )
                    console.print(f"Detection ID: [cyan]{history_id}[/cyan]")
                
                progress.update(task, completed=100)
            
            # Display results
            console.print(f"[green]✓ Anomaly detection completed![/green]")
            
            # Show detection results
            table = Table(title="Detection Results")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Total Samples", str(results['total_samples']))
            table.add_row("Anomalies Detected", str(results['anomalies_detected']))
            table.add_row("Anomaly Rate", f"{results['anomaly_rate']:.2%}")
            table.add_row("Detection Threshold", f"{results['threshold']:.6f}")
            table.add_row("Mean Reconstruction Error", f"{results['mean_reconstruction_error']:.6f}")
            
            console.print(table)
            
            # Save results to file if requested
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                console.print(f"Results saved to: [cyan]{args.output}[/cyan]")
            
            # Show sample anomalies
            if results['anomaly_indices']:
                console.print(f"\n[yellow]First 10 anomaly indices:[/yellow]")
                console.print(str(results['anomaly_indices'][:10]))
            
        except Exception as e:
            console.print(f"[red]Error during detection: {str(e)}[/red]")
            if args.verbose:
                console.print(traceback.format_exc())
    
    def handle_evaluate(self, args):
        """Handle model evaluation"""
        if not self.check_auth():
            return
        
        if not args.model_path:
            console.print("[red]Error: --model-path is required for evaluation[/red]")
            return
        
        if not args.test_data:
            console.print("[red]Error: --test-data is required for evaluation[/red]")
            return
        
        if not os.path.exists(args.test_data):
            console.print(f"[red]Error: Test data file not found: {args.test_data}[/red]")
            return
        
        if not os.path.exists(args.model_path):
            console.print(f"[red]Error: Model path not found: {args.model_path}[/red]")
            return
        
        try:
            with Progress() as progress:
                task = progress.add_task("[cyan]Evaluating model...", total=100)
                
                # Evaluate model
                metrics = self.trainer.evaluate_model(args.model_path, args.test_data)
                
                progress.update(task, completed=100)
            
            # Display results
            console.print(f"[green]✓ Model evaluation completed![/green]")
            
            # Show metrics
            table = Table(title="Evaluation Results")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Accuracy", f"{metrics['accuracy']:.4f}")
            table.add_row("Precision", f"{metrics['precision']:.4f}")
            table.add_row("Recall", f"{metrics['recall']:.4f}")
            table.add_row("F1-Score", f"{metrics['f1_score']:.4f}")
            table.add_row("Anomaly Rate", f"{metrics['anomaly_rate']:.2%}")
            table.add_row("Mean Reconstruction Error", f"{metrics['mean_reconstruction_error']:.6f}")
            
            console.print(table)
            
            # Save results to file if requested
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(metrics, f, indent=2)
                console.print(f"Results saved to: [cyan]{args.output}[/cyan]")
            
        except Exception as e:
            console.print(f"[red]Error during evaluation: {str(e)}[/red]")
            if args.verbose:
                console.print(traceback.format_exc())
    
    def handle_list_models(self, args):
        """List all models for current user"""
        if not self.check_auth():
            return
        
        user = self.auth.get_current_user()
        models = self.db.get_user_models(user['id'])
        
        if not models:
            console.print("[yellow]No models found in database[/yellow]")
            
            # Check for local models
            models_dir = "models"
            if os.path.exists(models_dir):
                local_models = []
                for item in os.listdir(models_dir):
                    item_path = os.path.join(models_dir, item)
                    if os.path.isdir(item_path):
                        # Check if it's a model directory
                        if os.path.exists(os.path.join(item_path, "metadata.joblib")):
                            local_models.append({
                                'name': item,
                                'path': item_path,
                                'local': True
                            })
                
                if local_models:
                    console.print("\n[yellow]Local models (not in database):[/yellow]")
                    table = Table(title="Local Models")
                    table.add_column("Name", style="cyan")
                    table.add_column("Path", style="green")
                    table.add_column("Status", style="yellow")
                    
                    for model in local_models:
                        table.add_row(model['name'], model['path'], "Local")
                    
                    console.print(table)
            
            return
        
        table = Table(title=f"Models for {user['username']}")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Accuracy", style="yellow")
        table.add_column("Created", style="blue")
        table.add_column("Samples", justify="right")
        table.add_column("Path", style="dim")
        
        for model in models:
            created = model['created_at'].strftime('%Y-%m-%d')
            accuracy = f"{model['accuracy']:.2%}" if model['accuracy'] else "N/A"
            samples = str(model['training_samples']) if model['training_samples'] else "N/A"
            
            table.add_row(
                str(model['id']),
                model['name'],
                accuracy,
                created,
                samples,
                model['model_path'][:50] + "..." if len(model['model_path']) > 50 else model['model_path']
            )
        
        console.print(table)
    
    def run(self):
        """Main CLI runner"""
        args = self.parser.parse_args()
        
        try:
            # Handle interactive mode
            if args.interactive and len(sys.argv) == 2:
                self.interactive_mode()
                return
            
            # Handle commands
            if args.version:
                self.handle_version(args)
            elif args.register:
                self.handle_register(args)
            elif args.login:
                self.handle_login(args)
            elif args.logout:
                self.handle_logout(args)
            elif args.train:
                self.handle_train(args)
            elif args.detect:
                self.handle_detect(args)
            elif args.evaluate:
                self.handle_evaluate(args)
            elif args.list_models:
                self.handle_list_models(args)
            elif args.model_info:
                self.handle_model_info(args)
            elif args.delete_model:
                self.handle_delete_model(args)
            else:
                # If no command specified, show help
                if len(sys.argv) == 1:
                    self.parser.print_help()
                else:
                    console.print("[red]Error: No valid command specified[/red]")
                    console.print("Use [cyan]ids-cli --help[/cyan] for usage information")
        
        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled by user[/yellow]")
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            if args.verbose:
                console.print(traceback.format_exc())
        finally:
            self.db.close()
    
    def interactive_mode(self):
        """Run in interactive mode"""
        console.print("[bold cyan]Intrusion Detection System - Interactive Mode[/bold cyan]")
        console.print("=" * 50)
        
        while True:
            console.print("\n[bold]Available Commands:[/bold]")
            console.print("  1. Register new user")
            console.print("  2. Login")
            console.print("  3. Train new model")
            console.print("  4. Detect anomalies")
            console.print("  5. Evaluate model")
            console.print("  6. List models")
            console.print("  7. Logout")
            console.print("  8. Exit")
            
            choice = input("\nEnter your choice (1-8): ").strip()
            
            if choice == "1":
                self.handle_register(argparse.Namespace(
                    interactive=True,
                    username=None,
                    password=None,
                    email=None
                ))
            elif choice == "2":
                self.handle_login(argparse.Namespace(
                    username=None,
                    password=None
                ))
            elif choice == "3":
                data_file = input("Enter data file path: ").strip()
                model_name = input("Enter model name: ").strip()
                self.handle_train(argparse.Namespace(
                    data_file=data_file,
                    model_name=model_name,
                    epochs=50,
                    learning_rate=1e-3,
                    verbose=False
                ))
            elif choice == "4":
                model_path = input("Enter model path: ").strip()
                data_file = input("Enter data file path: ").strip()
                output = input("Enter output file (optional): ").strip() or None
                self.handle_detect(argparse.Namespace(
                    model_path=model_path,
                    data_file=data_file,
                    output=output,
                    verbose=False
                ))
            elif choice == "5":
                model_path = input("Enter model path: ").strip()
                test_data = input("Enter test data file path: ").strip()
                output = input("Enter output file (optional): ").strip() or None
                self.handle_evaluate(argparse.Namespace(
                    model_path=model_path,
                    test_data=test_data,
                    output=output,
                    verbose=False
                ))
            elif choice == "6":
                self.handle_list_models(argparse.Namespace())
            elif choice == "7":
                self.handle_logout(argparse.Namespace())
            elif choice == "8":
                console.print("[green]Goodbye![/green]")
                break
            else:
                console.print("[red]Invalid choice. Please try again.[/red]")
    
    def handle_version(self, args):
        """Display version information"""
        console.print("[bold cyan]Intrusion Detection CLI[/bold cyan]")
        console.print("Version: 1.0.0")
        console.print("Model: Deterministic DCA + Denoising Autoencoder")
        console.print("Database: PostgreSQL (Neon)")
        console.print("Author: Intrusion Detection Team")
        console.print("License: MIT")
    
    def handle_model_info(self, args):
        """Get detailed model information"""
        if not args.model_info:
            console.print("[red]Error: --model-info requires a model path[/red]")
            return
        
        try:
            # Try to load the model
            model = IntrusionDetectionModel.load(args.model_info)
            
            # Display model info
            console.print(f"\n[bold cyan]Model Information[/bold cyan]")
            console.print("=" * 40)
            console.print(f"Model Path: [green]{args.model_info}[/green]")
            console.print(f"Input Features: [cyan]{model.autoencoder.input_dim}[/cyan]")
            console.print(f"Encoding Dimension: [cyan]{model.autoencoder.encoding_dim}[/cyan]")
            console.print(f"Noise Factor: [cyan]{model.autoencoder.noise_factor}[/cyan]")
            console.print(f"Detection Threshold: [cyan]{model.threshold:.6f}[/cyan]")
            
            if model.metrics:
                console.print(f"\n[bold]Metrics:[/bold]")
                for key, value in model.metrics.items():
                    console.print(f"  {key}: [green]{value}[/green]")
            
            # Check if model is in database
            if self.auth.is_authenticated():
                user = self.auth.get_current_user()
                db_model = self.db.get_model_by_path(args.model_info, user['id'])
                if db_model:
                    console.print(f"\n[bold]Database Info:[/bold]")
                    console.print(f"  Model ID: [cyan]{db_model['id']}[/cyan]")
                    console.print(f"  Name: [cyan]{db_model['name']}[/cyan]")
                    console.print(f"  Created: [cyan]{db_model['created_at']}[/cyan]")
            
        except Exception as e:
            console.print(f"[red]Error loading model: {str(e)}[/red]")
            if args.verbose:
                console.print(traceback.format_exc())
    
    def handle_logout(self, args):
        """Handle user logout"""
        if self.auth.current_session:
            self.auth.logout(self.auth.current_session)
            console.print("[green]✓ Logged out successfully[/green]")
        else:
            console.print("[yellow]You are not logged in[/yellow]")
    
    def handle_delete_model(self, args):
        """Delete a model"""
        if not self.check_auth():
            return
        
        if not args.delete_model:
            console.print("[red]Error: --delete-model requires a model path[/red]")
            return
        
        user = self.auth.get_current_user()
        
        # Check if model is in database
        db_model = self.db.get_model_by_path(args.delete_model, user['id'])
        
        # Confirm deletion
        console.print(f"[yellow]Warning: This will delete model at path:[/yellow]")
        console.print(f"[yellow]{args.delete_model}[/yellow]")
        
        if db_model:
            console.print(f"[yellow]Database entry will also be removed (ID: {db_model['id']})[/yellow]")
        
        confirm = input("Are you sure? (yes/no): ")
        
        if confirm.lower() == 'yes':
            try:
                # Delete from database if exists
                if db_model:
                    self.db.delete_model(db_model['id'], user['id'])
                    console.print(f"[green]✓ Database entry removed[/green]")
                
                # Delete local files
                import shutil
                if os.path.exists(args.delete_model):
                    shutil.rmtree(args.delete_model)
                    console.print(f"[green]✓ Local files deleted[/green]")
                else:
                    console.print("[yellow]Warning: Model path not found locally[/yellow]")
                
                console.print(f"[green]✓ Model deletion completed[/green]")
            except Exception as e:
                console.print(f"[red]Error deleting model: {e}[/red]")
        else:
            console.print("[yellow]Deletion cancelled[/yellow]")


def main():
    """Main entry point"""
    cli = IntrusionDetectionCLI()
    cli.run()

if __name__ == "__main__":
    main()