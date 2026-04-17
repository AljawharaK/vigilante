#!/usr/bin/env python3
"""
Vigilante Intrusion Detection System - GUI
Production version with real authentication and database integration
"""

import flet as ft
from flet import (
    Page, Container, Column, Row, Text, 
    TextField, Dropdown, dropdown,
    AlertDialog, TextButton, ProgressRing,
    Card, Icon, MainAxisAlignment, CrossAxisAlignment,
    Alignment, ThemeMode, ProgressBar,
    ButtonStyle, RoundedRectangleBorder, Animation, AnimationCurve,
    ControlState,
)
import asyncio
import queue
import os
import sys
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from importlib import resources
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def _resolve_logo_path() -> str:
    """Resolve the path to Vigilante_logo.png for GUI - checks root directory first"""
    
    # Get the project root directory
    current_dir = Path(__file__).parent.absolute()  # This is intrusion_detection/
    project_root = current_dir.parent  # This is vigilante/
    
    # Method 1: Check in project root (simplest and most reliable)
    logo = project_root / 'Vigilante_logo.png'
    if logo.exists():
        return str(logo)
    
    # Method 2: Check in intrusion_detection/assets/
    assets_logo = current_dir / 'assets' / 'Vigilante_logo.png'
    if assets_logo.exists():
        return str(assets_logo)
    
    # Method 3: Check in current working directory
    cwd_logo = Path.cwd() / 'Vigilante_logo.png'
    if cwd_logo.exists():
        return str(cwd_logo)
    
    print("GUI: Logo not found in any location")
    return str(logo)  # Return the root path even if it doesn't exist

logo_path = _resolve_logo_path()
# Import real modules
from intrusion_detection.database import DatabaseManager
from intrusion_detection.auth import AuthManager
from intrusion_detection.model import IntrusionDetectionModel
from intrusion_detection.model_trainer import ModelTrainer
from intrusion_detection.utils import json_serializable

# =====================================================================
# THEME CONSTANTS
# =====================================================================

class AppTheme:
    """Application theme colors and styles"""
    
    # Primary colors - Dark cyber theme
    PRIMARY = "#BFA7F3"  # Lilac purple
    SECONDARY = "#1e293b"  # Lighter navy
    BACKGROUND = "#0f172a"  # Dark navy
    SURFACE = "#1e293b"  # Lighter navy
    ERROR = "#ef4444"  # Red
    SUCCESS = "#10b981"  # Green
    WARNING = "#f59e0b"  # Orange
    INFO = "#3b82f6"  # Blue
    
    # Text colors
    TEXT_PRIMARY = "#ffffff"
    TEXT_SECONDARY = "#94a3b8"
    
    # Border colors
    BORDER = "#334155"
    
    # Severity colors
    SEVERITY_CRITICAL = "#ef4444"  # Bright red
    SEVERITY_HIGH = "#f97316"  # Orange
    SEVERITY_MEDIUM = "#eab308"  # Yellow
    SEVERITY_LOW = "#10b981"  # Green
    SEVERITY_MINIMAL = "#3b82f6"  # Blue
    
    @classmethod
    def get_severity_color(cls, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            "Critical": cls.SEVERITY_CRITICAL,
            "High": cls.SEVERITY_HIGH,
            "Medium": cls.SEVERITY_MEDIUM,
            "Low": cls.SEVERITY_LOW,
            "Minimal": cls.SEVERITY_MINIMAL
        }
        return colors.get(severity, cls.TEXT_PRIMARY)


# =====================================================================
# MAIN GUI APPLICATION
# =====================================================================

class VigilanteGUI:
    """Main GUI Application Class with real authentication and database"""
    
    def __init__(self, page: Page):
        self.page = page
        
        # Initialize real database and auth
        self.db = DatabaseManager()
        self.auth = AuthManager(self.db)
        
        # Try to load session from environment (if coming from CLI)
        session_token = os.environ.get('VIGILANTE_SESSION_TOKEN')
        if session_token and self.auth.validate_session(session_token):
            print(f"✅ Session loaded for {self.auth.current_user['username']}")
        else:
            self.auth.current_user = None
            self.auth.current_session = None
            self.auth.current_role = None
        
        self.current_model = None
        self.file_path = None
        self.train_file = None
        self.model_dropdown = None
        self.detection_results = None
        self.trainer = ModelTrainer()
        
        # Queue for background tasks
        self.task_queue = queue.Queue()
        self.result_queue = queue.Queue()
        
        # Setup page
        self.setup_page()
        
        # Setup UI based on auth state
        if self.auth.is_authenticated():
            self.setup_authenticated_ui()
        else:
            self.setup_login_ui()
        
        # Start background task processor
        self.page.run_task(self.process_tasks)

    def setup_page(self):
        """Configure page settings"""
        self.page.title = "Vigilante - Intrusion Detection System"
        self.page.theme_mode = ThemeMode.DARK
        self.page.bgcolor = AppTheme.BACKGROUND
        self.page.padding = 0
        self.page.spacing = 0
        self.page.window.width = 1300
        self.page.window.height = 800
        self.page.window.min_width = 1000
        self.page.window.min_height = 600
        
        # Set custom theme
        self.page.theme = ft.Theme(
            color_scheme_seed=AppTheme.PRIMARY,
        )
    
    def setup_login_ui(self):
        """Setup login interface"""
        # Create login form
        self.username_field = TextField(
            label="Username",
            prefix_icon=ft.Icons.PERSON,
            border_color=AppTheme.PRIMARY,
            focused_border_color=AppTheme.PRIMARY,
            width=300,
        )
        
        self.password_field = TextField(
            label="Password",
            prefix_icon=ft.Icons.LOCK,
            password=True,
            can_reveal_password=True,
            border_color=AppTheme.PRIMARY,
            focused_border_color=AppTheme.PRIMARY,
            width=300,
        )
        
        self.otp_field = TextField(
            label="OTP Code (sent to your email)",
            prefix_icon=ft.Icons.PIN,
            border_color=AppTheme.PRIMARY,
            focused_border_color=AppTheme.PRIMARY,
            width=300,
            visible=False,
        )
        
        self.login_button = ft.Button(
            "Login",
            icon=ft.Icons.LOGIN,
            on_click=self.handle_login,
            style=ButtonStyle(
                color=AppTheme.BACKGROUND,
                bgcolor=AppTheme.PRIMARY,
                shape=RoundedRectangleBorder(radius=8),
            ),
            width=300,
            height=45,
        )
        
        self.verify_otp_button = ft.Button(
            "Verify OTP",
            icon=ft.Icons.VERIFIED,
            on_click=self.handle_verify_otp,
            style=ButtonStyle(
                color=AppTheme.BACKGROUND,
                bgcolor=AppTheme.SUCCESS,
                shape=RoundedRectangleBorder(radius=8),
            ),
            width=300,
            height=45,
            visible=False,
        )
        
        self.login_status = Text("", color=AppTheme.TEXT_SECONDARY)
        
        # Create login container
        login_container = Container(
            content=Column(
                controls=[
                    ft.Image(
                        src=logo_path,
                        width=80,
                        height=80,
                    ),
                    Text("VIGILANTE", size=32, weight=ft.FontWeight.BOLD, color=AppTheme.PRIMARY),
                    Text("Intrusion Detection System", size=16, color=AppTheme.TEXT_SECONDARY),
                    Container(height=30),
                    self.username_field,
                    Container(height=10),
                    self.password_field,
                    Container(height=10),
                    self.otp_field,
                    Container(height=20),
                    self.login_button,
                    self.verify_otp_button,
                    Container(height=10),
                    self.login_status,
                ],
                horizontal_alignment=CrossAxisAlignment.CENTER,
                spacing=5,
            ),
            width=400,
            padding=ft.Padding.all(40),
            bgcolor=AppTheme.SURFACE,
            border_radius=ft.BorderRadius.all(20),
            border=ft.Border.all(2, AppTheme.PRIMARY + "40"),
        )
        
        # Center on page
        main_layout = Container(
            content=Row(
                controls=[login_container],
                alignment=MainAxisAlignment.CENTER,
                vertical_alignment=CrossAxisAlignment.CENTER,
            ),
            expand=True,
        )
        
        self.page.clean()
        self.page.add(main_layout)
        self.page.update()
    
    def handle_login(self, e):
        """Handle login button click"""
        username = self.username_field.value
        password = self.password_field.value
        
        if not username or not password:
            self.login_status.value = "Please enter username and password"
            self.login_status.color = AppTheme.ERROR
            self.page.update()
            return
        
        # Disable login button
        self.login_button.disabled = True
        self.login_status.value = "Verifying credentials..."
        self.login_status.color = AppTheme.INFO
        self.page.update()
        
        # Run login in background
        self.page.run_task(self._async_login, username, password)
    
    async def _async_login(self, username: str, password: str):
        """Async login process"""
        try:
            # Step 1: Login with credentials
            result = await self.run_in_thread(
                self.auth.login, username, password
            )
            
            if not result['success']:
                self.login_status.value = result['message']
                self.login_status.color = AppTheme.ERROR
                self.login_button.disabled = False
                self.page.update()
                return
            
            # Check if password needs to be changed
            if result.get('requires_password_change'):
                self.show_change_password_dialog(result['user_id'])
                return
            
            # Show OTP field
            self.login_status.value = f"OTP sent to {result['email']}"
            self.login_status.color = AppTheme.SUCCESS
            self.otp_field.visible = True
            self.verify_otp_button.visible = True
            self.login_button.visible = False
            self.page.update()
            
        except Exception as e:
            self.login_status.value = f"Login failed: {str(e)}"
            self.login_status.color = AppTheme.ERROR
            self.login_button.disabled = False
            self.page.update()
    
    def handle_verify_otp(self, e):
        """Handle OTP verification"""
        otp_code = self.otp_field.value
        
        if not otp_code:
            self.login_status.value = "Please enter OTP code"
            self.login_status.color = AppTheme.ERROR
            self.page.update()
            return
        
        # Disable verify button
        self.verify_otp_button.disabled = True
        self.login_status.value = "Verifying OTP..."
        self.login_status.color = AppTheme.INFO
        self.page.update()
        
        # Run OTP verification in background
        self.page.run_task(self._async_verify_otp, otp_code)
    
    async def _async_verify_otp(self, otp_code: str):
        """Async OTP verification"""
        try:
            result = await self.run_in_thread(
                self.auth.verify_otp, otp_code
            )
            
            if result['success']:
                # Login successful
                self.setup_authenticated_ui()
            else:
                self.login_status.value = result['message']
                self.login_status.color = AppTheme.ERROR
                self.verify_otp_button.disabled = False
                self.page.update()
                
        except Exception as e:
            self.login_status.value = f"OTP verification failed: {str(e)}"
            self.login_status.color = AppTheme.ERROR
            self.verify_otp_button.disabled = False
            self.page.update()
    
    def show_change_password_dialog(self, user_id: int):
        """Show change password dialog"""
        new_pass = TextField(
            label="New Password",
            password=True,
            can_reveal_password=True,
            width=300,
        )
        confirm_pass = TextField(
            label="Confirm Password",
            password=True,
            can_reveal_password=True,
            width=300,
        )
        
        def change_password(e):
            if new_pass.value != confirm_pass.value:
                self.show_dialog("Error", "Passwords do not match")
                return
            if len(new_pass.value) < 8:
                self.show_dialog("Error", "Password must be at least 8 characters")
                return
            
            # Update password
            try:
                password_hash = self.auth.hash_password(new_pass.value)
                self.db.reset_user_password(user_id, password_hash, must_change=False)
                self.close_dialog()
                self.show_dialog("Success", "Password changed successfully. Please login again.")
            except Exception as e:
                self.show_dialog("Error", f"Failed to change password: {str(e)}")
        
        dialog = AlertDialog(
            title=Text("Change Password Required"),
            content=Column(
                controls=[
                    Text("You must change your password before logging in."),
                    Container(height=10),
                    new_pass,
                    confirm_pass,
                ],
                width=350,
                height=200,
            ),
            actions=[
                TextButton("Cancel", on_click=lambda e: self.close_dialog()),
                TextButton("Change Password", on_click=change_password),
            ],
        )
        
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()
    
    def setup_authenticated_ui(self):
        """Setup main UI for authenticated user"""
        # Clear page
        self.page.clean()
        
        # Create navigation rail based on role
        self.nav_rail = self.create_navigation_rail()
        
        # Create main content area - start with dashboard
        self.content_container = Container(
            expand=True,
            bgcolor=AppTheme.SURFACE,
            border_radius=ft.BorderRadius.all(10),
            padding=ft.Padding.all(20),
            margin=ft.Margin.only(left=10, top=10, right=10, bottom=10),
            content=self.create_dashboard_content()
        )
        
        # Create header with role badge
        header = self.create_header()
        
        # Main layout
        main_layout = Column(
            controls=[
                header,
                Row(
                    controls=[
                        self.nav_rail,
                        self.content_container,
                    ],
                    expand=True,
                    spacing=0,
                )
            ],
            spacing=0,
            expand=True,
        )
        
        self.page.add(main_layout)
        self.page.update()
    
    def create_header(self) -> Container:
        """Create application header with role badge"""
        
        # Determine role badge color
        role_icon = ft.Icons.ADMIN_PANEL_SETTINGS if self.auth.is_admin() else ft.Icons.VISIBILITY
        
        # Safely get username
        username = self.auth.current_user.get('username', 'Unknown') if self.auth.current_user else 'Unknown'
        
        return Container(
            content=Row(
                controls=[
                    Row(
                        controls=[
                            ft.Image(
                                src=logo_path,
                                width=70,
                                height=70,
                            ),
                            Text(
                                "VIGILANTE",
                                size=24,
                                weight=ft.FontWeight.BOLD,
                                color=AppTheme.PRIMARY,
                            ),
                            Text(
                                "Intrusion Detection System",
                                size=16,
                                color=AppTheme.TEXT_SECONDARY,
                            ),
                        ],
                        spacing=10,
                    ),
                    Row(
                        controls=[
                            Container(
                                content=Row(
                                    controls=[
                                        Icon(role_icon, size=16, color="#000000"),
                                        Text(
                                            self.auth.current_role or "Analyst",
                                            size=14,
                                            color= AppTheme.BACKGROUND,
                                            weight=ft.FontWeight.BOLD,
                                        ),
                                        Text(
                                            f"({username})",
                                            size=14,
                                            color=AppTheme.BACKGROUND,
                                            weight=ft.FontWeight.BOLD,
                                        ),
                                    ],
                                    spacing=5,
                                ),
                                bgcolor=AppTheme.SUCCESS,
                                padding=ft.Padding.all(8),
                                border_radius=ft.BorderRadius.all(5),
                                border=ft.Border.all(1, AppTheme.SUCCESS ),
                            ), 
                            self.create_status_indicator(),
                        ],
                        spacing=10,
                    ),
                ],
                alignment=MainAxisAlignment.SPACE_BETWEEN,
            ),
            bgcolor=AppTheme.SECONDARY,
            padding=ft.Padding.all(15),
            border=ft.Border.all(1, AppTheme.BORDER),
        )
    
    def create_status_indicator(self) -> Container:
        """Create online status indicator"""
        return Container(
            width=10,
            height=10,
            bgcolor=AppTheme.SUCCESS,
            border_radius=ft.BorderRadius.all(5),
            animate=Animation(duration=300, curve=AnimationCurve.BOUNCE_OUT),
        )
    
    def create_navigation_rail(self) -> Container:
        """Create navigation rail based on user role"""
        
        nav_buttons = []
        
        # Dashboard is available to all roles
        nav_buttons.append(
            self.create_nav_button(ft.Icons.DASHBOARD, "Dashboard", "dashboard", True)
        )
        
        # Models page (available to all)
        nav_buttons.append(
            self.create_nav_button(ft.Icons.LIST, "View Models", "models", False)
        )
        
        # Admin-only pages
        if self.auth.is_admin():
            nav_buttons.extend([
                self.create_nav_button(ft.Icons.PEOPLE, "Manage Users", "manage_users", False),
                self.create_nav_button(ft.Icons.ADMIN_PANEL_SETTINGS, "System Admin", "system_admin", False),
            ])
        
        # Settings and logout available to all
        nav_buttons.extend([
            self.create_nav_button(ft.Icons.SETTINGS, "Settings", "settings", False),
        ])
        
        # Add all buttons to column
        buttons_column = Column(
            controls=nav_buttons,
            horizontal_alignment=CrossAxisAlignment.CENTER,
            spacing=5,
        )
        
        # Add logout button separately
        logout_button = self.create_nav_button(ft.Icons.LOGOUT, "Logout", "logout", False, AppTheme.ERROR)
        
        return Container(
            width=80,
            bgcolor=AppTheme.SECONDARY,
            border=ft.Border.all(1, AppTheme.BORDER),
            border_radius=ft.BorderRadius.all(10),
            margin=ft.Margin.all(10),
            content=Column(
                controls=[
                    # Logo/Icon at top
                    Container(
                        padding=ft.Padding.all(15),
                    ),
                    # Navigation buttons
                    Container(content=buttons_column, expand=True),
                    # Logout at bottom
                    logout_button,
                    Container(height=10),
                ],
                horizontal_alignment=CrossAxisAlignment.CENTER,
                spacing=0,
                expand=True,
            ),
        )
    
    def create_nav_button(self, icon_name, tooltip: str, view: str, 
                          selected: bool = False, color: str = None) -> Container:
        """Create a round navigation button"""
        return Container(
            content=ft.IconButton(
                icon=icon_name,
                icon_size=24,
                icon_color=color or (AppTheme.PRIMARY if selected else AppTheme.TEXT_SECONDARY),
                tooltip=tooltip,
                on_click=lambda e, v=view: self.navigate_to(v),
                style=ButtonStyle(
                    shape=RoundedRectangleBorder(radius=25),
                    bgcolor={ControlState.DEFAULT: AppTheme.SURFACE if selected else AppTheme.SECONDARY},
                ),
            ),
            padding=ft.Padding.all(10),
        )
    
    def navigate_to(self, view: str):
        """Handle navigation between views"""
        
        # Check permissions for admin-only pages
        if view in ["manage_users", "system_admin"] and not self.auth.is_admin():
            self.show_dialog("Access Denied", "This page is only accessible to Administrators.")
            return
        
        # Load appropriate view
        if view == "dashboard":
            content = self.create_dashboard_content()
        elif view == "models":
            content = self.create_models_content()
        elif view == "manage_users" and self.auth.is_admin():
            content = self.create_manage_users_content()
        elif view == "system_admin" and self.auth.is_admin():
            content = self.create_system_admin_content()
        elif view == "settings":
            content = self.create_settings_content()
        elif view == "logout":
            self.handle_logout()
            return
        else:
            content = self.create_dashboard_content()
        
        self.content_container.content = content
        self.page.update()
    
    def handle_logout(self):
        """Handle logout"""
        self.auth.logout()
        self.setup_login_ui()
    
    # =====================================================================
    # DASHBOARD VIEW
    # =====================================================================
    
    def create_dashboard_content(self) -> Container:
        """Create dashboard with statistics and recent detections"""
        
        # Get real stats from database
        stats = self.get_dashboard_stats()
        recent_detections = self.get_recent_detections()
        user_models = self.db.get_user_models(self.auth.current_user['id'])
        
        # Create stat cards
        stats_row = Row(
            controls=[
                self.create_stat_card("Total Detections", stats["total_detections"], ft.Icons.ANALYTICS),
                self.create_stat_card("Anomalies Found", stats["anomalies_found"], ft.Icons.WARNING, AppTheme.ERROR),
                self.create_stat_card("Models Trained", stats["models_trained"], ft.Icons.MODEL_TRAINING),
                self.create_stat_card("Last Detection", stats["last_detection"], ft.Icons.ACCESS_TIME),
            ],
            spacing=10,
        )
        
        # Create recent detections table
        detections_table = self.create_detections_table(recent_detections)
        
        # Create models list
        models_section = self.create_models_section(user_models)
        
        return Container(
            content=Column(
                controls=[
                    Text("Dashboard", size=24, weight=ft.FontWeight.BOLD),
                    Container(height=20),
                    stats_row,
                    Container(height=20),
                    Row(
                        controls=[
                            Container(
                                content=Column(
                                    controls=[
                                        Text("Recent Detections", size=18, weight=ft.FontWeight.BOLD),
                                        Container(height=10),
                                        detections_table,
                                    ],
                                    spacing=0,
                                    expand=True,
                                ),
                                expand=1,
                                bgcolor=AppTheme.SECONDARY,
                                padding=ft.Padding.all(20),
                                border_radius=ft.BorderRadius.all(10),
                                height=400,
                            ),
                            Container(
                                content=Column(
                                    controls=[
                                        Row(
                                            controls=[
                                                Text("My Models", size=18, weight=ft.FontWeight.BOLD),
                                                Text(f"({len(user_models)} total)", 
                                                     size=14, color=AppTheme.TEXT_SECONDARY),
                                            ],
                                            spacing=10,
                                        ),
                                        Container(height=10),
                                        models_section,
                                    ],
                                    spacing=0,
                                    expand=True,
                                ),
                                expand=1,
                                bgcolor=AppTheme.SECONDARY,
                                padding=ft.Padding.all(20),
                                border_radius=ft.BorderRadius.all(10),
                                height=400,
                            ),
                        ],
                        spacing=10,
                        expand=True,
                    ),
                ],
                spacing=0,
                expand=True,
            ),
            expand=True,
        )
    
    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get real dashboard statistics from database"""
        user_id = self.auth.current_user['id']
        
        try:
            # Get detection summary for last 30 days
            summary = self.db.get_detection_summary(user_id, 30)
            
            total_detections = sum(d.get('total_detections', 0) for d in summary)
            total_anomalies = sum(d.get('total_anomalies', 0) for d in summary)
            
            # Get user models
            models = self.db.get_user_models(user_id)
            models_count = len(models)
            
            # Get last detection time
            last_detection = "Never"
            if models:
                # Get most recent detection
                history = self.db.get_detection_history(user_id, 1)
                if history:
                    last_detection = history[0]['created_at'].strftime("%Y-%m-%d %H:%M")
            
            return {
                "total_detections": f"{total_detections:,}",
                "anomalies_found": f"{total_anomalies:,}",
                "models_trained": str(models_count),
                "last_detection": last_detection,
            }
            
        except Exception as e:
            print(f"Error getting dashboard stats: {e}")
            return {
                "total_detections": "0",
                "anomalies_found": "0",
                "models_trained": "0",
                "last_detection": "Error",
            }
    
    def get_recent_detections(self, limit: int = 10) -> List[Dict]:
        """Get recent detections from database"""
        user_id = self.auth.current_user['id']
        
        try:
            history = self.db.get_detection_history(user_id, limit)
            return history
        except Exception as e:
            print(f"Error getting recent detections: {e}")
            return []
    
    def create_detections_table(self, detections: List[Dict]) -> Container:
        """Create table of recent detections"""
        
        if not detections:
            return Container(
                content=Text("No recent detections", color=AppTheme.TEXT_SECONDARY),
                padding=ft.Padding.all(20),
            )
        
        # Create DataTable
        table = ft.DataTable(
            columns=[
                ft.DataColumn(Text("Date")),
                ft.DataColumn(Text("Model")),
                ft.DataColumn(Text("Total Flows")),
                ft.DataColumn(Text("Anomalies")),
                ft.DataColumn(Text("Rate")),
            ],
            rows=[
                ft.DataRow(
                    cells=[
                        ft.DataCell(Text(d['created_at'].strftime("%Y-%m-%d %H:%M") if hasattr(d['created_at'], 'strftime') else str(d['created_at'])[:16])),
                        ft.DataCell(Text(d.get('model_name', 'N/A')[:15])),
                        ft.DataCell(Text(f"{d['total_flows']:,}" if d['total_flows'] else "0")),
                        ft.DataCell(
                            Container(
                                content=Text(str(d['anomalies_detected'])),
                                bgcolor=AppTheme.ERROR if d['anomalies_detected'] > 0 else AppTheme.SUCCESS,
                                padding=ft.Padding.all(5),
                                border_radius=ft.BorderRadius.all(5),
                            )
                        ),
                        ft.DataCell(Text(f"{(d['anomalies_detected']/d['total_flows']*100):.1f}%" if d['total_flows'] and d['total_flows'] > 0 else "0%")),
                    ]
                )
                for d in detections
            ],
            heading_row_color=AppTheme.SURFACE,
            heading_row_height=40,
            data_row_color={ControlState.HOVERED: AppTheme.PRIMARY + "20"},
            column_spacing=20,
            divider_thickness=0,
        )
        
        return Container(
            content=Column(
                controls=[table],
                scroll=ft.ScrollMode.AUTO,
            ),
            height=250,
        )
    
    def create_models_section(self, models) -> Container:
        """Create a section displaying user's models"""
        
        if not models:
            return Container(
                content=Column(
                    controls=[
                        Icon(ft.Icons.INFO, size=40, color=AppTheme.TEXT_SECONDARY),
                        Text("No models trained yet", color=AppTheme.TEXT_SECONDARY),
                    ],
                    horizontal_alignment=CrossAxisAlignment.CENTER,
                    alignment=MainAxisAlignment.CENTER,
                ),
                alignment=Alignment.CENTER,
                expand=True,
            )
        
        # Create a list of model cards
        model_cards = []
        for model in models[:5]:  # Show top 5 models
            accuracy = model.get('accuracy', 0)
            accuracy_color = AppTheme.SUCCESS if accuracy > 0.9 else AppTheme.WARNING if accuracy > 0.7 else AppTheme.ERROR
            
            model_card = Container(
                content=Row(
                    controls=[
                        Icon(ft.Icons.MODEL_TRAINING, color=AppTheme.PRIMARY, size=20),
                        Column(
                            controls=[
                                Text(
                                    (model['name'][:20] + "..." if len(model['name']) > 20 else model['name']),
                                    size=14, 
                                    weight=ft.FontWeight.BOLD
                                ),
                                Text(
                                    f"Accuracy: {accuracy:.2%}" if accuracy else "N/A", 
                                    size=12, 
                                    color=accuracy_color
                                ),
                            ],
                            spacing=2,
                            expand=True,
                        ),
                        Text(
                            model['created_at'].strftime("%Y-%m-%d") if hasattr(model['created_at'], 'strftime') else "N/A",
                            size=12, 
                            color=AppTheme.TEXT_SECONDARY
                        ),
                    ],
                    spacing=10,
                ),
                padding=ft.Padding.all(10),
                border=ft.Border.all(1, AppTheme.BORDER),
                border_radius=ft.BorderRadius.all(5),
                margin=ft.Margin.only(bottom=5),
                on_click=lambda e, m=model: self.show_model_details(m),
            )
            model_cards.append(model_card)
        
        return Container(
            content=Column(
                controls=model_cards,
                scroll=ft.ScrollMode.AUTO,
                spacing=5,
            ),
            expand=True,
        )
    
    # =====================================================================
    # MODELS VIEW
    # =====================================================================
    
    def create_models_content(self) -> Container:
        """Create models list view"""
        
        # Get user's models
        user_models = self.db.get_user_models(self.auth.current_user['id'])
        
        if not user_models:
            return Container(
                content=Column(
                    controls=[
                        Icon(ft.Icons.INFO, size=60, color=AppTheme.TEXT_SECONDARY),
                        Text("No models trained yet", size=18, color=AppTheme.TEXT_SECONDARY),
                    ],
                    horizontal_alignment=CrossAxisAlignment.CENTER,
                    alignment=MainAxisAlignment.CENTER,
                ),
                alignment=Alignment.CENTER,
                expand=True,
            )
        
        # Create models table
        models_table = ft.DataTable(
            columns=[
                ft.DataColumn(Text("ID")),
                ft.DataColumn(Text("Name")),
                ft.DataColumn(Text("Type")),
                ft.DataColumn(Text("Accuracy")),
                ft.DataColumn(Text("Precision")),
                ft.DataColumn(Text("Recall")),
                ft.DataColumn(Text("F1")),
                ft.DataColumn(Text("Created")),
            ],
            rows=[
                ft.DataRow(
                    cells=[
                        ft.DataCell(Text(str(m.get('id', '')))),
                        ft.DataCell(Text(m.get('name', 'N/A')[:20])),
                        ft.DataCell(Text(m.get('model_type', 'rnsa_knn'))),
                        ft.DataCell(Text(f"{m.get('accuracy', 0):.2%}" if m.get('accuracy') else "N/A")),
                        ft.DataCell(Text(f"{m.get('precision', 0):.2%}" if m.get('precision') else "N/A")),
                        ft.DataCell(Text(f"{m.get('recall', 0):.2%}" if m.get('recall') else "N/A")),
                        ft.DataCell(Text(f"{m.get('f1_score', 0):.2%}" if m.get('f1_score') else "N/A")),
                        ft.DataCell(
                            Text(
                                m['created_at'].strftime("%Y-%m-%d")
                                if hasattr(m['created_at'], 'strftime')
                                else "N/A"
                            )
                        ),
                    ]
                )
                for m in user_models
            ],
            heading_row_color=AppTheme.SURFACE,
            heading_row_height=40,
            data_row_color={ControlState.HOVERED: AppTheme.PRIMARY + "20"},
            column_spacing=20,
            divider_thickness=0,
        )
        
        return Container(
            content=Column(
                controls=[
                    Row(
                        controls=[
                            Text("My Models", size=24, weight=ft.FontWeight.BOLD),
                        ],
                        alignment=MainAxisAlignment.SPACE_BETWEEN,
                    ),
                    Container(height=20),
                    
                    Container(
                        content=models_table,
                    ),
                ],
                spacing=0,
                expand=True,
                scroll=ft.ScrollMode.AUTO,  # Move scroll to Column instead of Container
            ),
            expand=True,
        )
    
    def show_model_details(self, model: Dict):
        """Show detailed model information"""
        details = f"""
Model ID: {model.get('id', 'N/A')}
Name: {model.get('name', 'N/A')}
Type: {model.get('model_type', 'rnsa_knn')}
Created: {model.get('created_at', 'N/A')}

Performance Metrics:
• Accuracy: {model.get('accuracy', 0):.2%}
• Precision: {model.get('precision', 0):.2%}
• Recall: {model.get('recall', 0):.2%}
• F1 Score: {model.get('f1_score', 0):.2%}

Training:
• Samples: {model.get('training_samples', 'N/A')}
• Features: {model.get('features_count', 'N/A')}

Path: {model.get('model_path', 'N/A')}
        """
        
        self.show_dialog(f"Model Details: {model.get('name', 'Unknown')}", details)
    
    # =====================================================================
    # ADMIN VIEWS
    # =====================================================================
    
    def create_manage_users_content(self) -> Container:
        """Create user management view (Admin only)"""
        
        # Get all users
        users = self.db.get_all_users()
        
        # Create users table with working buttons
        users_table = ft.DataTable(
            columns=[
                ft.DataColumn(Text("ID")),
                ft.DataColumn(Text("Username")),
                ft.DataColumn(Text("Email")),
                ft.DataColumn(Text("Role")),
                ft.DataColumn(Text("Status")),
                ft.DataColumn(Text("Last Login")),
                ft.DataColumn(Text("Actions")),
            ],
            rows=[
                ft.DataRow(
                    cells=[
                        ft.DataCell(Text(str(u.get('id', '')))),
                        ft.DataCell(Text(u.get('username', ''))),
                        ft.DataCell(Text(u.get('email', ''))),
                        ft.DataCell(Text(u.get('role_name', 'Analyst'))),
                        ft.DataCell(
                            Container(
                                content=Text("Active" if u.get('is_active', True) else "Inactive"),
                                bgcolor=AppTheme.SUCCESS if u.get('is_active', True) else AppTheme.ERROR,
                                padding=ft.Padding.all(5),
                                border_radius=ft.BorderRadius.all(5),
                            )
                        ),
                        ft.DataCell(
                            Text(
                                u['last_login'].strftime("%Y-%m-%d %H:%M") 
                                if u.get('last_login') and hasattr(u['last_login'], 'strftime')
                                else "Never"
                            )
                        ),
                        ft.DataCell(
                            Row(
                                controls=[
                                    ft.IconButton(
                                        icon=ft.Icons.EDIT,
                                        icon_color=AppTheme.PRIMARY,
                                        tooltip="Edit User",
                                        on_click=lambda e, user=u: self.show_edit_user_dialog(user),
                                    ),
                                    ft.IconButton(
                                        icon=ft.Icons.DELETE,
                                        icon_color=AppTheme.ERROR,
                                        tooltip="Delete User",
                                        on_click=lambda e, user=u: self.delete_user_working(user),
                                    ),
                                ],
                                spacing=5,
                            )
                        ),
                    ]
                )
                for u in users
            ],
            heading_row_color=AppTheme.SURFACE,
            heading_row_height=40,
            data_row_color={ControlState.HOVERED: AppTheme.PRIMARY + "20"},
            column_spacing=20,
            divider_thickness=0,
        )
        
        # Create new user button
        create_user_button = ft.Button(
            "Create New User",
            icon=ft.Icons.PERSON_ADD,
            on_click=self.show_create_user_dialog,
            style=ButtonStyle(
                color=AppTheme.BACKGROUND,
                bgcolor=AppTheme.PRIMARY,
                shape=RoundedRectangleBorder(radius=8),
            ),
        )
        
        return Container(
            content=Column(
                controls=[
                    Row(
                        controls=[
                            Text("Manage Users (Admin Only)", size=24, weight=ft.FontWeight.BOLD),
                            create_user_button,
                        ],
                        alignment=MainAxisAlignment.SPACE_BETWEEN,
                    ),
                    Container(height=20),
                    
                    Container(
                        content=Column(
                            controls=[users_table],
                            scroll=ft.ScrollMode.AUTO,
                            expand=True,
                        ),
                        expand=True,
                    ),
                ],
                spacing=0,
                expand=True,
            ),
            expand=True,
        )

    def show_create_user_dialog(self, e):
        """Show create user dialog"""
        username_field = TextField(label="Username", width=300)
        email_field = TextField(label="Email", width=300)
        password_field = TextField(label="Password", password=True, can_reveal_password=True, width=300)
        role_dropdown = Dropdown(
            label="Role",
            options=[
                dropdown.Option("Analyst"),
                dropdown.Option("Administrator"),
            ],
            value="Analyst",
            width=300,
        )

        def create_user_click(e):
            if not username_field.value or not email_field.value or not password_field.value:
                self.show_dialog("Error", "Please fill in all fields")
                return
            
            if len(password_field.value) < 8:
                self.show_dialog("Error", "Password must be at least 8 characters")
                return

            try:
                password_hash = self.auth.hash_password(password_field.value)
                self.db.create_user(
                    username=username_field.value,
                    password_hash=password_hash,
                    email=email_field.value,
                    role=role_dropdown.value,
                    created_by=self.auth.current_user['id'],
                    must_change_password=False
                )
                
                self.close_dialog()
                self.show_dialog("User Created", f"User '{username_field.value}' created successfully!")
                
                # Refresh the view
                self.content_container.content = self.create_manage_users_content()
                self.page.update()
                
            except Exception as ex:
                self.show_dialog("Error", f"Failed to create user: {str(ex)}")

        create_dialog = AlertDialog(
            title=Text("Create New User"),
            content=Column(
                controls=[username_field, email_field, password_field, role_dropdown],
                width=350,
                height=280,
                tight=True,
            ),
            actions=[
                TextButton("Cancel", on_click=lambda _: self.close_dialog()),
                TextButton("Create", on_click=create_user_click),
            ],
        )
        
        self.page.dialog = create_dialog
        create_dialog.open = True
        self.page.update()

    def show_edit_user_dialog(self, user: Dict):
        """Show edit user dialog"""
        role_dropdown = Dropdown(
            label="Role",
            options=[
                dropdown.Option("Analyst"),
                dropdown.Option("Administrator"),
            ],
            value=user.get('role_name', 'Analyst'),
            width=300,
        )

        def update_user_click(e):
            try:
                self.db.update_user_role(
                    user['id'],
                    role_dropdown.value,
                    self.auth.current_user['id']
                )
                
                self.db.log_audit_event(
                    user_id=self.auth.current_user['id'],
                    username=self.auth.current_user['username'],
                    action="user_role_update",
                    resource=user['username'],
                    status="success",
                    details={"new_role": role_dropdown.value}
                )
                
                self.close_dialog()
                self.show_dialog("Success", f"User '{user['username']}' updated")
                
                self.content_container.content = self.create_manage_users_content()
                self.page.update()
                
            except Exception as ex:
                self.show_dialog("Error", f"Failed to update user: {str(ex)}")

        edit_dialog = AlertDialog(
            title=Text(f"Edit User: {user['username']}"),
            content=Column(
                controls=[
                    Text(f"Email: {user['email']}", color=AppTheme.TEXT_SECONDARY),
                    Container(height=10),
                    role_dropdown,
                ],
                width=350,
                height=150,
                tight=True,
            ),
            actions=[
                TextButton("Cancel", on_click=lambda _: self.close_dialog()),
                TextButton("Update", on_click=update_user_click),
            ],
        )
        
        self.page.dialog = edit_dialog
        edit_dialog.open = True
        self.page.update()

    def deactivate_user(self, user: Dict):
        """Deactivate a user"""
        def confirm_deactivate_click(e):
            try:
                if user.get('role_name') == 'Administrator' and self.db.count_admins() <= 1:
                    self.close_dialog()
                    self.show_dialog("Error", "Cannot deactivate the last Administrator.")
                    return
                
                self.db.deactivate_user(user['id'], self.auth.current_user['id'])
                self.db.invalidate_user_sessions(user['id'])
                
                self.close_dialog()
                self.show_dialog("Success", f"User '{user['username']}' deactivated.")
                
                self.content_container.content = self.create_manage_users_content()
                self.page.update()
                
            except Exception as ex:
                self.close_dialog()
                self.show_dialog("Error", f"Deactivation failed: {str(ex)}")

        deactivate_dialog = AlertDialog(
            title=Text("Confirm Deactivation"),
            content=Text(f"Are you sure you want to disable account: {user['username']}?"),
            actions=[
                TextButton("Cancel", on_click=lambda _: self.close_dialog()),
                TextButton("Deactivate", on_click=confirm_deactivate_click),
            ],
        )
        
        self.page.dialog = deactivate_dialog
        deactivate_dialog.open = True
        self.page.update()

    def show_change_password_dialog_ui(self, e):
        """Show change password dialog from settings"""
        curr_pass = TextField(label="Current Password", password=True, can_reveal_password=True)
        new_pass = TextField(label="New Password", password=True, can_reveal_password=True)
        conf_pass = TextField(label="Confirm New Password", password=True, can_reveal_password=True)
        
        def change_click(e):
            if not curr_pass.value or not new_pass.value:
                self.show_dialog("Error", "All fields are required.")
                return
            if new_pass.value != conf_pass.value:
                self.show_dialog("Error", "New passwords do not match.")
                return
            
            try:
                result = self.auth.change_password(self.auth.current_user['id'], curr_pass.value, new_pass.value)
                if result.get('success'):
                    self.close_dialog()
                    self.show_dialog("Success", "Password updated successfully.")
                else:
                    self.show_dialog("Error", result.get('message', "Failed to change password."))
            except Exception as ex:
                self.show_dialog("Error", str(ex))

        pass_dialog = AlertDialog(
            title=Text("Change Password"),
            content=Column([curr_pass, new_pass, conf_pass], width=350, height=250, tight=True),
            actions=[
                TextButton("Cancel", on_click=lambda _: self.close_dialog()),
                TextButton("Update", on_click=change_click),
            ],
        )
        
        self.page.dialog = pass_dialog
        pass_dialog.open = True
        self.page.update()

    def show_dialog(self, title: str, message: str):
        """Legacy helper to show info dialogs"""
        info_dialog = AlertDialog(
            title=Text(title),
            content=Text(message),
            actions=[TextButton("OK", on_click=lambda _: self.close_dialog())],
        )
        self.page.dialog = info_dialog
        info_dialog.open = True
        self.page.update()

    def close_dialog(self, e=None):
        """Standardized close for version 0.82.0"""
        if self.page.dialog:
            self.page.dialog.open = False
            self.page.update()

    def delete_user_working(self, user: Dict):
        """Delete/deactivate a user with confirmation"""
        
        def confirm_delete(e):
            try:
                # Prevent deleting the only admin
                if user.get('role_name') == 'Administrator':
                    admin_count = self.db.count_admins()
                    if admin_count <= 1:
                        self.show_dialog("Error", "Cannot delete the only Administrator")
                        self.close_dialog()
                        return
                
                # Prevent self-deletion
                if user['id'] == self.auth.current_user['id']:
                    self.show_dialog("Error", "You cannot delete your own account")
                    self.close_dialog()
                    return
                
                # Deactivate user
                self.deactivate_user(user['id'], self.auth.current_user['id'])
                
                # Invalidate all sessions for this user
                self.db.invalidate_user_sessions(user['id'])
                
                # Log the action
                self.db.log_audit_event(
                    user_id=self.auth.current_user['id'],
                    username=self.auth.current_user['username'],
                    action="user_delete",
                    resource=user['username'],
                    status="success"
                )
                
                self.close_dialog()
                self.show_dialog("Success", f"User '{user['username']}' has been deactivated")
                
                # Refresh the manage users page
                self.content_container.content = self.create_manage_users_content()
                self.page.update()
                
            except Exception as e:
                self.close_dialog()
                self.show_dialog("Error", f"Failed to delete user: {str(e)}")
        
        dialog = AlertDialog(
            title=Text("Confirm Deactivation"),
            content=Text(f"Are you sure you want to deactivate user '{user['username']}'?\n\nThis action can be reversed by an administrator."),
            actions=[
                TextButton("Cancel", on_click=lambda e: self.close_dialog()),
                TextButton("Deactivate", on_click=confirm_delete, style=ButtonStyle(color=AppTheme.ERROR)),
            ],
        )
        
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()


    # =====================================================================
    # 3: SETTINGS VIEW
    # =====================================================================
    
    def create_system_admin_content(self) -> Container:
        """Create system administration view"""
        
        # Get database stats
        db_stats = self.db.get_database_stats()
        
        # Get audit logs
        audit_logs = self.db.get_audit_logs(30)
        
        # Convert tuple results to dict for each log if needed
        log_dicts = []
        for log in audit_logs:
            if isinstance(log, dict):
                log_dict = log
            elif isinstance(log, tuple):
                # Convert tuple to dict using expected structure
                log_dict = {
                    'id': log[0] if len(log) > 0 else '',
                    'created_at': log[1] if len(log) > 1 else datetime.now(),
                    'username': log[2] if len(log) > 2 else 'System',
                    'action': log[3] if len(log) > 3 else '',
                    'resource': log[4] if len(log) > 4 else '-',
                    'status': log[5] if len(log) > 5 else 'success',
                }
            else:
                continue
            log_dicts.append(log_dict)
        
        # Create audit logs card with proper sizing
        audit_card = Card(
            content=Container(
                content=Column(
                    controls=[
                        Text("Recent Audit Logs", size=18, weight=ft.FontWeight.BOLD),
                        Container(height=10),
                        self.create_audit_logs_table(log_dicts[:10]),
                    ],
                    spacing=0,
                    expand=True,  # Make Column expand
                ),
                padding=ft.Padding.all(20),
                expand=True,  # Make Container expand
            ),
            expand=True,  # Make card expand to fill available space
        )
        
        return Container(
            content=Column(
                controls=[
                    Text("System Administration", size=24, weight=ft.FontWeight.BOLD),
                    Container(height=20),
                    
                    # Stats cards row
                    Container(
                        content=Row(
                            controls=[
                                self.create_stat_card("Total Users", str(db_stats.get('counts', {}).get('user_count', 0)), ft.Icons.PEOPLE),
                                self.create_stat_card("Total Models", str(db_stats.get('counts', {}).get('model_count', 0)), ft.Icons.MODEL_TRAINING),
                                self.create_stat_card("Total Detections", str(db_stats.get('counts', {}).get('detection_count', 0)), ft.Icons.ANALYTICS),
                                self.create_stat_card("Active Sessions", str(db_stats.get('counts', {}).get('active_sessions', 0)), ft.Icons.LOGIN),
                            ],
                            spacing=10,
                            expand=True,
                        ),
                        height=120,  # Fixed height for stats cards
                    ),
                    
                    Container(height=20),
                    
                    # Audit logs card - takes remaining space
                    Container(
                        content=audit_card,
                        expand=True,  # This container expands to fill remaining space
                    ),
                ],
                spacing=0,
                expand=True,
            ),
            expand=True,
        )
    
    def create_audit_logs_table(self, logs: List[Dict]) -> Container:
        """Create audit logs table"""
        
        if not logs:
            return Container(
                content=Text("No audit logs found", color=AppTheme.TEXT_SECONDARY),
                padding=ft.Padding.all(20),
            )
        
        # Filter out None values in logs
        filtered_logs = [log for log in logs if log is not None]
        
        table = ft.DataTable(
            columns=[
                ft.DataColumn(Text("Time", size=12)),
                ft.DataColumn(Text("User", size=12)),
                ft.DataColumn(Text("Action", size=12)),
                ft.DataColumn(Text("Resource", size=12)),
                ft.DataColumn(Text("Status", size=12)),
            ],
            rows=[
                ft.DataRow(
                    cells=[
                        ft.DataCell(Text(
                            log['created_at'].strftime("%Y-%m-%d %H:%M") 
                            if hasattr(log['created_at'], 'strftime') 
                            else str(log.get('created_at', ''))[:16],
                            size=11
                        )),
                        ft.DataCell(Text(log.get('username', 'System'), size=11)),
                        ft.DataCell(Text(log.get('action', ''), size=11)),
                        ft.DataCell(Text(str(log.get('resource', '-'))[:25] if log.get('resource') else '-', size=11)),
                        ft.DataCell(
                            Container(
                                content=Text(log.get('status', 'success'), size=11),
                                bgcolor=AppTheme.SUCCESS if log.get('status') == 'success' else AppTheme.ERROR,
                                padding=ft.Padding.all(3),
                                border_radius=ft.BorderRadius.all(5),
                            )
                        ),
                    ]
                )
                for log in filtered_logs
            ],
            heading_row_color=AppTheme.SURFACE,
            heading_row_height=35,
            data_row_color={ControlState.HOVERED: AppTheme.PRIMARY + "20"},
            column_spacing=15,
            divider_thickness=0,
            vertical_lines=ft.BorderSide(0, "transparent"),
            horizontal_lines=ft.BorderSide(0, "transparent"),
        )
        
        # Make table scrollable - apply scroll to Column, not Container
        return Container(
            content=Column(
                controls=[
                    Container(
                        content=table,
                        height=300,  # Fixed height for scrollable area
                    ),
                ],
                spacing=0,
                scroll=ft.ScrollMode.AUTO,  # Move scroll to Column
            ),
            expand=True,
        )
    
    # =====================================================================
    # SETTINGS VIEW
    # =====================================================================
    
    def create_settings_content(self) -> Container:
        """Create settings interface"""
        
        # Get fresh user data from database to ensure email is available
        user_id = self.auth.current_user.get('id') if self.auth.current_user else None
        email_display = "Not available"
        username_display = "Unknown"
        role_display = self.auth.current_role or 'Analyst'
        
        if user_id:
            try:
                # Get fresh user data from database
                user_data = self.db.get_user_by_id(user_id)
                if user_data:
                    email_display = user_data.get('email', 'Not available')
                    username_display = user_data.get('username', 'Unknown')
            except Exception as e:
                print(f"Error getting user email: {e}")
                # Fallback to current_user data
                if self.auth.current_user:
                    email_display = self.auth.current_user.get('email', 'Not available')
                    username_display = self.auth.current_user.get('username', 'Unknown')
        else:
            if self.auth.current_user:
                username_display = self.auth.current_user.get('username', 'Unknown')
                email_display = self.auth.current_user.get('email', 'Not available')
        
        return Container(
            content=Column(
                controls=[
                    Text("Settings", size=24, weight=ft.FontWeight.BOLD),
                    Container(height=20),
                    
                    Card(
                        content=Container(
                            content=Column(
                                controls=[
                                    Text("User Profile", size=18, weight=ft.FontWeight.BOLD),
                                    Container(height=10),
                                    
                                    self.create_list_tile(
                                        leading=Icon(ft.Icons.PERSON, color=AppTheme.PRIMARY),
                                        title=Text(f"Username: {username_display}"),
                                    ),
                                    
                                    self.create_list_tile(
                                        leading=Icon(ft.Icons.EMAIL, color=AppTheme.PRIMARY),
                                        title=Text(f"Email: {email_display}"),
                                    ),
                                    
                                    self.create_list_tile(
                                        leading=Icon(ft.Icons.ADMIN_PANEL_SETTINGS, color=AppTheme.PRIMARY),
                                        title=Text(f"Role: {role_display}"),
                                    ),
                                    
                                    Container(height=20),
                                    
                                    ft.Button(
                                        "Change Password",
                                        icon=ft.Icons.LOCK_RESET,
                                        on_click=self.show_change_password_dialog_ui,
                                        style=ButtonStyle(
                                            color=AppTheme.PRIMARY,
                                            shape=RoundedRectangleBorder(radius=8),
                                        ),
                                    ),
                                ],
                                spacing=0,
                            ),
                            padding=ft.Padding.all(20),
                        ),
                    ),
                    
                    Container(height=20),
                    
                    Card(
                        content=Container(
                            content=Column(
                                controls=[
                                    Text("System Information", size=18, weight=ft.FontWeight.BOLD),
                                    Container(height=10),
                                    
                                    self.create_list_tile(
                                        leading=Icon(ft.Icons.COMPUTER, color=AppTheme.PRIMARY),
                                        title=Text("System: Vigilante IDS"),
                                    ),
                                    
                                    self.create_list_tile(
                                        leading=Icon(ft.Icons.DATASET, color=AppTheme.PRIMARY),
                                        title=Text("Database: PostgreSQL (Neon)"),
                                    ),
                                    
                                    self.create_list_tile(
                                        leading=Icon(ft.Icons.MODEL_TRAINING, color=AppTheme.PRIMARY),
                                        title=Text("Model: RNSA + KNN"),
                                    ),
                                ],
                                spacing=0,
                            ),
                            padding=ft.Padding.all(20),
                        ),
                    ),
                ],
                spacing=0,
                expand=True,
            ),
            expand=True,
        )
    
    # =====================================================================
    # UTILITY METHODS
    # =====================================================================
    
    def create_list_tile(self, leading=None, title=None, subtitle=None, trailing=None):
        """Create a list tile"""
        controls = []
        if leading:
            controls.append(leading)
        
        text_col = Column(
            controls=[],
            spacing=0,
        )
        if title:
            text_col.controls.append(title)
        if subtitle:
            text_col.controls.append(subtitle)
        
        controls.append(Container(content=text_col, expand=True))
        
        if trailing:
            controls.append(trailing)
        
        return Row(
            controls=controls,
            vertical_alignment=CrossAxisAlignment.CENTER,
            spacing=10,
        )
    
    def create_stat_card(self, title: str, value: str, icon_name, color: str = None) -> Container:
        """Create a statistics card"""
        return Container(
            content=Column(
                controls=[
                    Icon(icon_name, color=color or AppTheme.PRIMARY, size=30),
                    Text(value, size=24, weight=ft.FontWeight.BOLD, color=color or AppTheme.PRIMARY),
                    Text(title, size=14, color=AppTheme.TEXT_SECONDARY),
                ],
                horizontal_alignment=CrossAxisAlignment.CENTER,
                spacing=5,
            ),
            expand=True,
            bgcolor=AppTheme.SECONDARY,
            padding=ft.Padding.all(20),
            border_radius=ft.BorderRadius.all(10),
            border=ft.Border.all(1, AppTheme.BORDER),
        )
    
    def close_dialog(self):
        """Close the current dialog"""
        if self.page.dialog:
            self.page.dialog.open = False
            self.page.update()
    
    def show_dialog(self, title: str, message: str):
        """Show a dialog"""
        dialog = AlertDialog(
            title=Text(title),
            content=Text(message),
            actions=[
                TextButton("OK", on_click=lambda e: self.close_dialog()),
            ],
        )
        
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()
    
    # =====================================================================
    # ASYNC HELPERS
    # =====================================================================
    
    async def run_in_thread(self, func, *args, **kwargs):
        """Run a function in a thread pool"""
        return await asyncio.get_event_loop().run_in_executor(
            None, lambda: func(*args, **kwargs)
        )
    
    async def process_tasks(self):
        """Process background tasks"""
        while True:
            try:
                # Check for results
                while not self.result_queue.empty():
                    result = self.result_queue.get_nowait()
                    # Handle result (placeholder)
                
                await asyncio.sleep(0.1)
                
            except Exception as e:
                print(f"Error in task processor: {e}")
                await asyncio.sleep(1)


# =====================================================================
# MAIN ENTRY POINT
# =====================================================================

def main(page: Page):
    """Main GUI entry point"""
    app = VigilanteGUI(page)


if __name__ == "__main__":
    # Check if flet is installed
    try:
        import flet
        print(f"Flet version: {flet.__version__}")
    except ImportError:
        print("Error: flet is not installed.")
        print("Please install it with: pip install flet")
        sys.exit(1)
    
    # Check for session token from CLI
    session_token = os.environ.get('VIGILANTE_SESSION_TOKEN')
    if session_token:
        print("Starting Vigilante GUI with existing session...")
    else:
        print("Starting Vigilante GUI...")
        print("Please login to continue.")
    
    # Run the app
    ft.app(target=main)