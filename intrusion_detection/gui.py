#!/usr/bin/env python3
"""
Vigilante Intrusion Detection System - Interactive GUI
Built with Flet - Modern Python GUI framework
"""

import flet as ft
from flet import (
    Page, Container, Column, Row, Text, 
    ElevatedButton, TextField, Dropdown, dropdown,
    AlertDialog, TextButton, ProgressRing,
    Card, Icon, icons, colors, margin, padding,
    border, border_radius, alignment, MainAxisAlignment,
    CrossAxisAlignment, ThemeMode, Tabs, Tab,
    ListView, ProgressBar, FilePicker, FilePickerResultEvent
)
import asyncio
import threading
import queue
import json
import os
import sys
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import pandas as pd
import numpy as np
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import Vigilante modules
from intrusion_detection.database import DatabaseManager
from intrusion_detection.auth import AuthManager
from intrusion_detection.model import IntrusionDetectionModel
from intrusion_detection.model_trainer import ModelTrainer
from intrusion_detection.utils import get_system_info

# =====================================================================
# THEME CONSTANTS - Modern Cyber Security Style
# =====================================================================

class AppTheme:
    """Application theme colors and styles"""
    
    # Primary colors - Dark cyber theme
    PRIMARY = "#BFA7F3"  # Lilac purple
    SECONDARY = "#Bc316A"  # Pinkish red
    BACKGROUND = "#160C40"  # Dark navy
    SURFACE = "#1e293b"  # Lighter navy
    ERROR = "#ff4d4d"  # Red
    SUCCESS = "#4caf50"  # Green
    WARNING = "#ff9800"  # Orange
    INFO = "#2196f3"  # Blue
    
    # Text colors
    TEXT_PRIMARY = "#ffffff"
    TEXT_SECONDARY = "#94a3b8"
    
    # Border colors
    BORDER = "#334155"
    
    # Severity colors
    SEVERITY_CRITICAL = "#ff1744"  # Bright red
    SEVERITY_HIGH = "#ff9100"  # Orange
    SEVERITY_MEDIUM = "#ffea00"  # Yellow
    SEVERITY_LOW = "#00e676"  # Green
    SEVERITY_MINIMAL = "#2979ff"  # Blue
    
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
    """Main GUI Application Class"""
    
    def __init__(self, page: Page):
        self.page = page
        self.db = DatabaseManager()
        self.auth = AuthManager(self.db)
        self.trainer = ModelTrainer()
        self.current_model = None
        self.session_file = Path.home() / ".vigilante_session"
        
        # File pickers
        self.file_picker = FilePicker()
        self.page.overlay.append(self.file_picker)
        
        # Queue for background tasks
        self.task_queue = queue.Queue()
        self.result_queue = queue.Queue()
        
        # Setup page
        self.setup_page()
        
        # Load session if exists
        self.load_session()
        
        # Setup UI
        self.setup_ui()
        
        # Start background task processor
        self.page.run_task(self.process_tasks)
        
    def setup_page(self):
        """Configure page settings"""
        self.page.title = "Vigilante - Intrusion Detection System"
        self.page.theme_mode = ThemeMode.DARK
        self.page.bgcolor = AppTheme.BACKGROUND
        self.page.padding = 0
        self.page.spacing = 0
        self.page.window_width = 1200
        self.page.window_height = 800
        self.page.window_min_width = 800
        self.page.window_min_height = 600
        
        # Set custom theme
        self.page.theme = ft.Theme(
            color_scheme_seed=AppTheme.PRIMARY,
            visual_density=ft.ThemeVisualDensity.COMFORTABLE,
        )
        
    def setup_ui(self):
        """Initialize UI components"""
        
        # Create navigation rail
        self.nav_rail = self.create_navigation_rail()
        
        # Create main content area
        self.content_container = Container(
            expand=True,
            bgcolor=AppTheme.SURFACE,
            border_radius=border_radius.all(10),
            padding=padding.all(20),
            margin=margin.only(left=10, top=10, right=10, bottom=10),
            content=self.create_login_content()
        )
        
        # Create header
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
        
    def create_header(self) -> Container:
        """Create application header"""
        return Container(
            content=Row(
                controls=[
                    Row(
                        controls=[
                            Icon(
                                ft.icons.SECURITY,
                                color=AppTheme.PRIMARY,
                                size=30,
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
                    Container(
                        content=Row(
                            controls=[
                                self.create_status_indicator(),
                                Text(
                                    "System Online",
                                    size=14,
                                    color=AppTheme.SUCCESS,
                                ),
                            ],
                            spacing=5,
                        ),
                        margin=margin.only(right=20),
                    ),
                ],
                alignment=MainAxisAlignment.SPACE_BETWEEN,
            ),
            bgcolor=AppTheme.SECONDARY,
            padding=padding.all(15),
            border=border.all(1, AppTheme.BORDER),
        )
        
    def create_status_indicator(self) -> Container:
        """Create online status indicator"""
        return Container(
            width=10,
            height=10,
            bgcolor=AppTheme.SUCCESS,
            border_radius=border_radius.all(5),
            animate=ft.animation.Animation(1000, "BOUNCE"),
        )
        
    def create_navigation_rail(self) -> Container:
        """Create navigation rail with round buttons"""
        return Container(
            width=80,
            bgcolor=AppTheme.SECONDARY,
            border=border.all(1, AppTheme.BORDER),
            border_radius=border_radius.all(10),
            margin=margin.all(10),
            content=Column(
                controls=[
                    # Logo/Icon at top
                    Container(
                        content=Icon(
                            ft.icons.SHIELD_MOON,
                            color=AppTheme.PRIMARY,
                            size=40,
                        ),
                        padding=padding.all(15),
                    ),
                    
                    # Navigation buttons
                    self.create_nav_button(ft.icons.DASHBOARD, "Dashboard", "dashboard", True),
                    self.create_nav_button(ft.icons.ANALYTICS, "Detection", "detection"),
                    self.create_nav_button(ft.icons.MODEL_TRAINING, "Training", "training"),
                    self.create_nav_button(ft.icons.HISTORY, "History", "history"),
                    self.create_nav_button(ft.icons.SETTINGS, "Settings", "settings"),
                    
                    # Spacer to push logout to bottom
                    Container(expand=True),
                    
                    # Logout button at bottom
                    self.create_nav_button(ft.icons.LOGOUT, "Logout", "logout", False, AppTheme.ERROR),
                ],
                horizontal_alignment=CrossAxisAlignment.CENTER,
                spacing=5,
            ),
        )
        
    def create_nav_button(self, icon: str, tooltip: str, view: str, 
                          selected: bool = False, color: str = None) -> Container:
        """Create a round navigation button"""
        return Container(
            content=ft.IconButton(
                icon=icon,
                icon_size=24,
                icon_color=color or (AppTheme.PRIMARY if selected else AppTheme.TEXT_SECONDARY),
                tooltip=tooltip,
                on_click=lambda e, v=view: self.navigate_to(v),
                style=ft.ButtonStyle(
                    shape=ft.RoundedRectangleBorder(radius=25),
                    bgcolor={
                        ft.MaterialState.DEFAULT: AppTheme.SURFACE if selected else AppTheme.SECONDARY,
                        ft.MaterialState.HOVERED: AppTheme.PRIMARY + "20",
                    },
                ),
            ),
            padding=padding.all(10),
        )
        
    def navigate_to(self, view: str):
        """Handle navigation between views"""
        # Load appropriate view
        if view == "dashboard":
            content = self.create_dashboard_content()
        elif view == "detection":
            content = self.create_detection_content()
        elif view == "training":
            content = self.create_training_content()
        elif view == "history":
            content = self.create_history_content()
        elif view == "settings":
            content = self.create_settings_content()
        elif view == "logout":
            self.logout()
            content = self.create_login_content()
        else:
            content = self.create_dashboard_content()
            
        self.content_container.content = content
        self.page.update()
        
    def create_login_content(self) -> Container:
        """Create login screen"""
        self.email_field = TextField(
            label="Email",
            hint_text="Enter your email",
            prefix_icon=ft.icons.EMAIL,
            border_color=AppTheme.PRIMARY,
            width=300,
        )
        
        self.password_field = TextField(
            label="Password",
            hint_text="Enter your password",
            password=True,
            can_reveal_password=True,
            prefix_icon=ft.icons.LOCK,
            border_color=AppTheme.PRIMARY,
            width=300,
        )
        
        self.otp_field = TextField(
            label="OTP Code",
            hint_text="Enter 6-digit OTP",
            prefix_icon=ft.icons.PIN,
            border_color=AppTheme.PRIMARY,
            width=300,
            visible=False,
        )
        
        self.login_status = Text("", size=12)
        self.login_progress = ProgressRing(visible=False, width=30, height=30)
        
        login_card = Container(
            content=Column(
                controls=[
                    Icon(ft.icons.SECURITY, color=AppTheme.PRIMARY, size=60),
                    Text("VIGILANTE", size=32, weight=ft.FontWeight.BOLD, color=AppTheme.PRIMARY),
                    Text("Intrusion Detection System", size=16, color=AppTheme.TEXT_SECONDARY),
                    Container(height=30),
                    self.email_field,
                    Container(height=10),
                    self.password_field,
                    Container(height=10),
                    self.otp_field,
                    Container(height=20),
                    Row(
                        controls=[
                            ElevatedButton(
                                "Login",
                                on_click=self.handle_login,
                                style=ft.ButtonStyle(
                                    color=AppTheme.SECONDARY,
                                    bgcolor=AppTheme.PRIMARY,
                                    shape=ft.RoundedRectangleBorder(radius=8),
                                ),
                            ),
                            self.login_progress,
                        ],
                        alignment=MainAxisAlignment.CENTER,
                        spacing=10,
                    ),
                    self.login_status,
                ],
                horizontal_alignment=CrossAxisAlignment.CENTER,
                spacing=5,
            ),
            width=400,
            padding=padding.all(40),
            bgcolor=AppTheme.SURFACE,
            border_radius=border_radius.all(20),
            border=border.all(2, AppTheme.PRIMARY + "40"),
        )
        
        return Container(
            content=Row(
                controls=[login_card],
                alignment=MainAxisAlignment.CENTER,
                vertical_alignment=CrossAxisAlignment.CENTER,
            ),
            expand=True,
        )
        
    async def handle_login(self, e):
        """Handle login button click"""
        email = self.email_field.value
        password = self.password_field.value
        otp = self.otp_field.value if self.otp_field.visible else None
        
        if not email or not password:
            self.login_status.value = "Please enter email and password"
            self.login_status.color = AppTheme.ERROR
            self.page.update()
            return
            
        self.login_progress.visible = True
        self.login_status.value = ""
        self.page.update()
        
        # Run login in thread to avoid blocking UI
        result = await self.run_in_thread(
            self.perform_login, email, password, otp
        )
        
        self.login_progress.visible = False
        
        if result["success"]:
            if result.get("requires_otp"):
                # Show OTP field
                self.otp_field.visible = True
                self.login_status.value = "OTP sent to your email"
                self.login_status.color = AppTheme.INFO
            else:
                # Login complete
                self.save_session()
                self.navigate_to("dashboard")
        else:
            self.login_status.value = result["message"]
            self.login_status.color = AppTheme.ERROR
            
        self.page.update()
        
    def perform_login(self, email: str, password: str, otp: str = None):
        """Perform login (runs in thread)"""
        try:
            # Extract username from email (simplified - adjust as needed)
            username = email.split('@')[0]
            
            if otp:
                # Verify OTP
                return self.auth.verify_otp(otp)
            else:
                # Initial login
                return self.auth.login(username, password)
        except Exception as e:
            return {"success": False, "message": str(e)}
            
    def create_dashboard_content(self) -> Container:
        """Create dashboard with statistics"""
        
        # Get stats
        stats = self.get_dashboard_stats()
        
        # Create stat cards
        stats_row = Row(
            controls=[
                self.create_stat_card("Total Detections", stats["total_detections"], ft.icons.ANALYTICS),
                self.create_stat_card("Anomalies Found", stats["anomalies_found"], ft.icons.WARNING, AppTheme.ERROR),
                self.create_stat_card("Models Trained", stats["models_trained"], ft.icons.MODEL_TRAINING),
                self.create_stat_card("System Uptime", stats["uptime"], ft.icons.ACCESS_TIME),
            ],
            spacing=10,
        )
        
        # Create recent anomalies table (using Flet DataTable)
        anomalies_table = self.create_anomalies_table(stats["recent_anomalies"])
        
        # Create chart placeholder
        chart = self.create_chart_placeholder()
        
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
                                        Text("Recent Anomalies", size=18, weight=ft.FontWeight.BOLD),
                                        Container(height=10),
                                        anomalies_table,
                                    ],
                                    spacing=0,
                                    expand=True,
                                ),
                                expand=1,
                                bgcolor=AppTheme.SECONDARY,
                                padding=padding.all(20),
                                border_radius=border_radius.all(10),
                                height=400,
                            ),
                            Container(
                                content=Column(
                                    controls=[
                                        Text("Detection Trends", size=18, weight=ft.FontWeight.BOLD),
                                        Container(height=10),
                                        chart,
                                    ],
                                    spacing=0,
                                    expand=True,
                                ),
                                expand=1,
                                bgcolor=AppTheme.SECONDARY,
                                padding=padding.all(20),
                                border_radius=border_radius.all(10),
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
        
    def create_stat_card(self, title: str, value: str, icon: str, color: str = None) -> Container:
        """Create a statistics card"""
        return Container(
            content=Column(
                controls=[
                    Icon(icon, color=color or AppTheme.PRIMARY, size=30),
                    Text(value, size=24, weight=ft.FontWeight.BOLD, color=color or AppTheme.PRIMARY),
                    Text(title, size=14, color=AppTheme.TEXT_SECONDARY),
                ],
                horizontal_alignment=CrossAxisAlignment.CENTER,
                spacing=5,
            ),
            expand=True,
            bgcolor=AppTheme.SECONDARY,
            padding=padding.all(20),
            border_radius=border_radius.all(10),
            border=border.all(1, AppTheme.BORDER),
        )
        
    def create_anomalies_table(self, anomalies: List[Dict]) -> Container:
        """Create table of recent anomalies using Flet DataTable"""
        
        if not anomalies:
            return Container(
                content=Text("No recent anomalies", color=AppTheme.TEXT_SECONDARY),
                padding=padding.all(20),
            )
            
        # Create DataTable with proper Flet syntax
        table = ft.DataTable(
            columns=[
                ft.DataColumn(Text("Date")),
                ft.DataColumn(Text("Source")),
                ft.DataColumn(Text("Destination")),
                ft.DataColumn(Text("Confidence")),
            ],
            rows=[
                ft.DataRow(
                    cells=[
                        ft.DataCell(Text(a.get("detected_at", "N/A")[:10] if a.get("detected_at") else "N/A")),
                        ft.DataCell(Text(a.get("src_ip", "N/A"))),
                        ft.DataCell(Text(a.get("dst_ip", "N/A"))),
                        ft.DataCell(
                            Container(
                                content=Text(f"{a.get('confidence', 0):.2f}"),
                                bgcolor=AppTheme.get_severity_color(a.get("severity", "Low")),
                                padding=padding.all(5),
                                border_radius=border_radius.all(5),
                            )
                        ),
                    ]
                )
                for a in anomalies[:5]
            ],
            heading_row_color=AppTheme.SURFACE,
            heading_row_height=40,
            data_row_color={ft.MaterialState.HOVERED: AppTheme.PRIMARY + "20"},
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
        
    def create_chart_placeholder(self) -> Container:
        """Create placeholder for charts"""
        return Container(
            content=Column(
                controls=[
                    Icon(ft.icons.SHOW_CHART, size=50, color=AppTheme.TEXT_SECONDARY),
                    Text("Chart visualization will appear here", color=AppTheme.TEXT_SECONDARY),
                ],
                horizontal_alignment=CrossAxisAlignment.CENTER,
                alignment=MainAxisAlignment.CENTER,
            ),
            alignment=alignment.center,
            expand=True,
        )
        
    def create_detection_content(self) -> Container:
        """Create detection interface"""
        
        # File picker display
        self.file_path = TextField(
            label="Input File",
            hint_text="Select CSV file for detection",
            read_only=True,
            expand=True,
        )
        
        # Model selection
        models = self.get_user_models()
        self.model_dropdown = Dropdown(
            label="Select Model",
            hint_text="Choose a trained model",
            options=[
                dropdown.Option(key=str(m["id"]), text=m["name"][:30])
                for m in models
            ] if models else [dropdown.Option(key="", text="No models available")],
            width=300,
        )
        
        # Results area
        self.detection_results = Container(
            content=Text("No detection results yet", color=AppTheme.TEXT_SECONDARY),
            bgcolor=AppTheme.SECONDARY,
            border_radius=border_radius.all(10),
            padding=padding.all(20),
            expand=True,
        )
        
        return Container(
            content=Column(
                controls=[
                    Text("Anomaly Detection", size=24, weight=ft.FontWeight.BOLD),
                    Container(height=20),
                    
                    # Input section
                    Card(
                        content=Container(
                            content=Column(
                                controls=[
                                    Text("Input Configuration", size=18, weight=ft.FontWeight.BOLD),
                                    Container(height=10),
                                    Row(
                                        controls=[
                                            self.file_path,
                                            ElevatedButton(
                                                "Browse",
                                                icon=ft.icons.FOLDER_OPEN,
                                                on_click=self.pick_file,
                                                style=ft.ButtonStyle(
                                                    color=AppTheme.PRIMARY,
                                                    shape=ft.RoundedRectangleBorder(radius=8),
                                                ),
                                            ),
                                        ],
                                        spacing=10,
                                    ),
                                    Container(height=10),
                                    Row(
                                        controls=[
                                            self.model_dropdown,
                                            ElevatedButton(
                                                "Run Detection",
                                                icon=ft.icons.PLAY_ARROW,
                                                on_click=self.run_detection,
                                                style=ft.ButtonStyle(
                                                    color=AppTheme.SECONDARY,
                                                    bgcolor=AppTheme.PRIMARY,
                                                    shape=ft.RoundedRectangleBorder(radius=8),
                                                ),
                                            ),
                                        ],
                                        spacing=10,
                                    ),
                                ],
                                spacing=0,
                            ),
                            padding=padding.all(20),
                        ),
                    ),
                    
                    Container(height=20),
                    
                    # Results section
                    Text("Detection Results", size=18, weight=ft.FontWeight.BOLD),
                    Container(height=10),
                    self.detection_results,
                ],
                spacing=0,
                expand=True,
            ),
            expand=True,
        )
        
    def create_training_content(self) -> Container:
        """Create model training interface"""
        
        # Training parameters
        self.train_file = TextField(
            label="Training Data",
            hint_text="Select CSV file for training",
            read_only=True,
            expand=True,
        )
        
        self.model_name = TextField(
            label="Model Name",
            hint_text="Enter a name for this model",
            width=300,
        )
        
        self.r_s_value = TextField(
            label="Self Radius (r_s)",
            hint_text="0.01",
            value="0.01",
            width=150,
        )
        
        self.max_detectors = TextField(
            label="Max Detectors",
            hint_text="1000",
            value="1000",
            width=150,
        )
        
        self.k_value = TextField(
            label="K (neighbors)",
            hint_text="1",
            value="1",
            width=150,
        )
        
        # Training progress
        self.training_progress = ProgressBar(
            width=600,
            visible=False,
        )
        
        self.training_status = Text("", color=AppTheme.TEXT_SECONDARY)
        
        # Recent models table
        recent_models_table = self.create_recent_models_table()
        
        return Container(
            content=Column(
                controls=[
                    Text("Model Training", size=24, weight=ft.FontWeight.BOLD),
                    Container(height=20),
                    
                    # Training configuration card
                    Card(
                        content=Container(
                            content=Column(
                                controls=[
                                    Text("Training Configuration", size=18, weight=ft.FontWeight.BOLD),
                                    Container(height=10),
                                    
                                    Row(
                                        controls=[
                                            self.train_file,
                                            ElevatedButton(
                                                "Browse",
                                                icon=ft.icons.FOLDER_OPEN,
                                                on_click=self.pick_training_file,
                                                style=ft.ButtonStyle(
                                                    color=AppTheme.PRIMARY,
                                                    shape=ft.RoundedRectangleBorder(radius=8),
                                                ),
                                            ),
                                        ],
                                        spacing=10,
                                    ),
                                    
                                    Container(height=10),
                                    
                                    Row(
                                        controls=[
                                            self.model_name,
                                        ],
                                        spacing=10,
                                    ),
                                    
                                    Container(height=10),
                                    
                                    Row(
                                        controls=[
                                            self.r_s_value,
                                            self.max_detectors,
                                            self.k_value,
                                        ],
                                        spacing=10,
                                    ),
                                    
                                    Container(height=20),
                                    
                                    Row(
                                        controls=[
                                            ElevatedButton(
                                                "Start Training",
                                                icon=ft.icons.TRAIN,
                                                on_click=self.start_training,
                                                style=ft.ButtonStyle(
                                                    color=AppTheme.SECONDARY,
                                                    bgcolor=AppTheme.PRIMARY,
                                                    shape=ft.RoundedRectangleBorder(radius=8),
                                                ),
                                            ),
                                            self.training_progress,
                                        ],
                                        spacing=20,
                                        vertical_alignment=CrossAxisAlignment.CENTER,
                                    ),
                                    
                                    Container(height=10),
                                    self.training_status,
                                ],
                                spacing=0,
                            ),
                            padding=padding.all(20),
                        ),
                    ),
                    
                    Container(height=20),
                    
                    # Recent models card
                    Card(
                        content=Container(
                            content=Column(
                                controls=[
                                    Text("Recent Models", size=18, weight=ft.FontWeight.BOLD),
                                    Container(height=10),
                                    recent_models_table,
                                ],
                                spacing=0,
                                expand=True,
                            ),
                            padding=padding.all(20),
                            height=300,
                        ),
                        expand=True,
                    ),
                ],
                spacing=0,
                expand=True,
            ),
            expand=True,
        )
        
    def create_history_content(self) -> Container:
        """Create detection history view"""
        
        # Get detection history
        history = self.get_detection_history()
        
        if not history:
            return Container(
                content=Column(
                    controls=[
                        Text("Detection History", size=24, weight=ft.FontWeight.BOLD),
                        Container(height=20),
                        Container(
                            content=Column(
                                controls=[
                                    Icon(ft.icons.HISTORY, size=50, color=AppTheme.TEXT_SECONDARY),
                                    Text("No detection history available", color=AppTheme.TEXT_SECONDARY),
                                ],
                                horizontal_alignment=CrossAxisAlignment.CENTER,
                                alignment=MainAxisAlignment.CENTER,
                            ),
                            alignment=alignment.center,
                            expand=True,
                        ),
                    ],
                    spacing=0,
                    expand=True,
                ),
                expand=True,
            )
            
        # Create DataTable for history
        table = ft.DataTable(
            columns=[
                ft.DataColumn(Text("Date")),
                ft.DataColumn(Text("Model")),
                ft.DataColumn(Text("Total Flows")),
                ft.DataColumn(Text("Anomalies")),
                ft.DataColumn(Text("Rate")),
                ft.DataColumn(Text("Actions")),
            ],
            rows=[
                ft.DataRow(
                    cells=[
                        ft.DataCell(Text(h["created_at"][:10] if h.get("created_at") else "N/A")),
                        ft.DataCell(Text(h.get("model_name", "N/A")[:15])),
                        ft.DataCell(Text(str(h.get("total_flows", 0)))),
                        ft.DataCell(Text(str(h.get("anomalies_detected", 0)))),
                        ft.DataCell(
                            Text(
                                f"{h['anomalies_detected']/h['total_flows']*100:.1f}%" 
                                if h.get('total_flows', 0) > 0 else "0%"
                            )
                        ),
                        ft.DataCell(
                            ft.IconButton(
                                icon=ft.icons.VISIBILITY,
                                icon_color=AppTheme.PRIMARY,
                                tooltip="View Details",
                                on_click=lambda e, i=h: self.view_detection_details(i),
                            )
                        ),
                    ]
                )
                for h in history[:20]
            ],
            heading_row_color=AppTheme.SURFACE,
            heading_row_height=40,
            data_row_color={ft.MaterialState.HOVERED: AppTheme.PRIMARY + "20"},
            column_spacing=20,
            divider_thickness=0,
        )
        
        return Container(
            content=Column(
                controls=[
                    Text("Detection History", size=24, weight=ft.FontWeight.BOLD),
                    Container(height=20),
                    
                    Container(
                        content=Column(
                            controls=[table],
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
        
    def create_settings_content(self) -> Container:
        """Create settings interface"""
        
        user = self.auth.current_user or {}
        
        return Container(
            content=Column(
                controls=[
                    Text("Settings", size=24, weight=ft.FontWeight.BOLD),
                    Container(height=20),
                    
                    Card(
                        content=Container(
                            content=Column(
                                controls=[
                                    Text("User Settings", size=18, weight=ft.FontWeight.BOLD),
                                    Container(height=10),
                                    
                                    ListTile(
                                        leading=Icon(ft.icons.PERSON, color=AppTheme.PRIMARY),
                                        title=Text(f"Username: {user.get('username', 'N/A')}"),
                                    ),
                                    
                                    ListTile(
                                        leading=Icon(ft.icons.EMAIL, color=AppTheme.PRIMARY),
                                        title=Text(f"Email: {user.get('email', 'N/A')}"),
                                    ),
                                    
                                    ListTile(
                                        leading=Icon(ft.icons.ADMIN_PANEL_SETTINGS, color=AppTheme.PRIMARY),
                                        title=Text(f"Role: {self.auth.current_role or 'N/A'}"),
                                    ),
                                    
                                    Container(height=20),
                                    
                                    ElevatedButton(
                                        "Change Password",
                                        icon=ft.icons.LOCK_RESET,
                                        on_click=self.change_password,
                                        style=ft.ButtonStyle(
                                            color=AppTheme.PRIMARY,
                                            shape=ft.RoundedRectangleBorder(radius=8),
                                        ),
                                    ),
                                ],
                                spacing=0,
                            ),
                            padding=padding.all(20),
                        ),
                    ),
                    
                    Container(height=20),
                    
                    Card(
                        content=Container(
                            content=Column(
                                controls=[
                                    Text("System Information", size=18, weight=ft.FontWeight.BOLD),
                                    Container(height=10),
                                    
                                    ListTile(
                                        leading=Icon(ft.icons.COMPUTER, color=AppTheme.PRIMARY),
                                        title=Text(f"System: {os.name}"),
                                    ),
                                    
                                    ListTile(
                                        leading=Icon(ft.icons.DATABASE, color=AppTheme.PRIMARY),
                                        title=Text("Database: Connected"),
                                    ),
                                    
                                    ListTile(
                                        leading=Icon(ft.icons.MODEL_TRAINING, color=AppTheme.PRIMARY),
                                        title=Text(f"Models: {len(self.get_user_models())}"),
                                    ),
                                ],
                                spacing=0,
                            ),
                            padding=padding.all(20),
                        ),
                    ),
                ],
                spacing=0,
                expand=True,
            ),
            expand=True,
        )
        
    def create_recent_models_table(self) -> Container:
        """Create table of recent models"""
        
        models = self.get_user_models()[:5]
        
        if not models:
            return Container(
                content=Text("No models trained yet", color=AppTheme.TEXT_SECONDARY),
                padding=padding.all(20),
            )
            
        table = ft.DataTable(
            columns=[
                ft.DataColumn(Text("Model")),
                ft.DataColumn(Text("Date")),
                ft.DataColumn(Text("Accuracy")),
                ft.DataColumn(Text("Detectors")),
            ],
            rows=[
                ft.DataRow(
                    cells=[
                        ft.DataCell(Text(m["name"][:20])),
                        ft.DataCell(Text(m["created_at"][:10] if m.get("created_at") else "N/A")),
                        ft.DataCell(Text(f"{m.get('accuracy', 0):.2%}")),
                        ft.DataCell(Text(str(m.get("detectors_count", "N/A")))),
                    ]
                )
                for m in models
            ],
            heading_row_color=AppTheme.SURFACE,
            heading_row_height=40,
            data_row_color={ft.MaterialState.HOVERED: AppTheme.PRIMARY + "20"},
            column_spacing=20,
            divider_thickness=0,
        )
        
        return Container(
            content=Column(
                controls=[table],
                scroll=ft.ScrollMode.AUTO,
                height=200,
            ),
        )
        
    # =====================================================================
    # EVENT HANDLERS
    # =====================================================================
    
    async def pick_file(self, e):
        """Open file picker for detection input"""
        def on_file_picked(e: FilePickerResultEvent):
            if e.files:
                self.file_path.value = e.files[0].path
                self.page.update()
                
        self.file_picker.on_result = on_file_picked
        self.file_picker.pick_files(
            allow_multiple=False,
            allowed_extensions=["csv"]
        )
        
    async def pick_training_file(self, e):
        """Open file picker for training data"""
        def on_file_picked(e: FilePickerResultEvent):
            if e.files:
                self.train_file.value = e.files[0].path
                self.page.update()
                
        self.file_picker.on_result = on_file_picked
        self.file_picker.pick_files(
            allow_multiple=False,
            allowed_extensions=["csv"]
        )
        
    async def run_detection(self, e):
        """Run anomaly detection"""
        if not self.file_path.value or not self.model_dropdown.value:
            await self.show_dialog("Error", "Please select input file and model")
            return
            
        self.detection_results.content = Column(
            controls=[
                ProgressRing(),
                Text("Running detection...", color=AppTheme.TEXT_SECONDARY),
            ],
            horizontal_alignment=CrossAxisAlignment.CENTER,
            alignment=MainAxisAlignment.CENTER,
        )
        self.page.update()
        
        # Run detection in thread
        result = await self.run_in_thread(
            self.perform_detection,
            self.file_path.value,
            int(self.model_dropdown.value)
        )
        
        if result["success"]:
            self.detection_results.content = self.create_detection_results_view(result["data"])
        else:
            self.detection_results.content = Text(
                f"Error: {result['message']}",
                color=AppTheme.ERROR,
            )
            
        self.page.update()
        
    def perform_detection(self, file_path: str, model_id: int) -> Dict:
        """Perform detection (runs in thread)"""
        try:
            # Get model
            model_data = self.db.get_model(model_id, self.auth.current_user['id'])
            if not model_data:
                return {"success": False, "message": "Model not found"}
                
            # Load model
            model = IntrusionDetectionModel.load(model_data['model_path'])
            
            # Load data
            df = pd.read_csv(file_path)
            
            # Detect anomalies
            X = model.preprocess_data(df, fit_scaler=False)
            predictions, confidence_scores = model.predict(X)
            
            # Prepare results
            anomalies = []
            anomaly_indices = np.where(predictions == 1)[0]
            
            for idx in anomaly_indices[:50]:
                anomalies.append({
                    "index": int(idx),
                    "confidence": float(confidence_scores[idx]),
                    "severity": self.calculate_severity(confidence_scores[idx]),
                })
                
            # Save to database
            results = {
                "total_flows": len(df),
                "anomalies_detected": len(anomalies),
                "anomalies": anomalies,
            }
            
            detection_id = self.db.save_detection(
                user_id=self.auth.current_user['id'],
                model_id=model_id,
                input_file=file_path,
                results=results
            )
            
            return {
                "success": True,
                "data": {
                    "detection_id": detection_id,
                    "total_flows": len(df),
                    "anomalies": anomalies,
                }
            }
            
        except Exception as e:
            return {"success": False, "message": str(e)}
            
    def create_detection_results_view(self, data: Dict) -> Container:
        """Create view for detection results"""
        
        # Summary stats
        stats_row = Row(
            controls=[
                self.create_stat_card(
                    "Total Flows",
                    str(data["total_flows"]),
                    ft.icons.DATA_USAGE
                ),
                self.create_stat_card(
                    "Anomalies Found",
                    str(len(data["anomalies"])),
                    ft.icons.WARNING,
                    AppTheme.ERROR
                ),
                self.create_stat_card(
                    "Detection Rate",
                    f"{len(data['anomalies'])/data['total_flows']*100:.1f}%",
                    ft.icons.PERCENT
                ),
            ],
            spacing=10,
        )
        
        # Anomalies list
        anomaly_list = Column(
            controls=[
                Container(
                    content=Row(
                        controls=[
                            Icon(ft.icons.WARNING, color=AppTheme.get_severity_color(a["severity"])),
                            Text(f"Flow #{a['index']} - Confidence: {a['confidence']:.2f}"),
                        ],
                        spacing=10,
                    ),
                    padding=padding.all(10),
                    border=border.all(1, AppTheme.BORDER),
                    border_radius=border_radius.all(5),
                    margin=margin.only(bottom=5),
                )
                for a in data["anomalies"][:20]
            ],
            scroll=ft.ScrollMode.AUTO,
            spacing=5,
        )
        
        return Column(
            controls=[
                stats_row,
                Container(height=20),
                Text(f"Detection ID: {data['detection_id']}", size=12, color=AppTheme.TEXT_SECONDARY),
                Container(height=10),
                Text("Detected Anomalies", size=16, weight=ft.FontWeight.BOLD),
                Container(height=10),
                Container(
                    content=anomaly_list,
                    height=300,
                ),
            ],
            spacing=0,
        )
        
    async def start_training(self, e):
        """Start model training"""
        if not self.train_file.value:
            await self.show_dialog("Error", "Please select training data file")
            return
            
        if not self.model_name.value:
            await self.show_dialog("Error", "Please enter a model name")
            return
            
        self.training_progress.visible = True
        self.training_status.value = "Training in progress..."
        self.training_status.color = AppTheme.INFO
        self.page.update()
        
        # Run training in thread
        result = await self.run_in_thread(
            self.perform_training,
            self.train_file.value,
            self.model_name.value,
            float(self.r_s_value.value),
            int(self.max_detectors.value),
            int(self.k_value.value)
        )
        
        self.training_progress.visible = False
        
        if result["success"]:
            self.training_status.value = f"Training complete! Model ID: {result['model_id']}"
            self.training_status.color = AppTheme.SUCCESS
        else:
            self.training_status.value = f"Error: {result['message']}"
            self.training_status.color = AppTheme.ERROR
            
        self.page.update()
        
    def perform_training(self, file_path: str, model_name: str, 
                        r_s: float, max_detectors: int, k: int) -> Dict:
        """Perform training (runs in thread)"""
        try:
            # Train model
            result = self.trainer.train_model(
                data_path=file_path,
                model_name=model_name,
                r_s=r_s,
                max_detectors=max_detectors,
                k=k,
                dataset_name=os.path.basename(file_path)
            )
            
            # Save to database
            model_id = self.db.save_model(
                user_id=self.auth.current_user['id'],
                model_name=result['model_name'],
                model_path=result['model_path'],
                dataset_name=os.path.basename(file_path),
                metrics=result['metrics'],
                features=None,
                parameters=result['parameters']
            )
            
            return {
                "success": True,
                "model_id": model_id
            }
            
        except Exception as e:
            return {"success": False, "message": str(e)}
            
    async def change_password(self, e):
        """Show change password dialog"""
        
        old_pass = TextField(label="Current Password", password=True)
        new_pass = TextField(label="New Password", password=True)
        confirm_pass = TextField(label="Confirm Password", password=True)
        
        async def confirm_change(e):
            if new_pass.value != confirm_pass.value:
                await self.show_dialog("Error", "Passwords do not match")
                return
                
            # Change password in thread
            result = await self.run_in_thread(
                self.auth.change_password,
                self.auth.current_user['id'],
                old_pass.value,
                new_pass.value
            )
            
            self.page.dialog.open = False
            
            if result["success"]:
                await self.show_dialog("Success", "Password changed successfully")
            else:
                await self.show_dialog("Error", result["message"])
                
            self.page.update()
            
        dialog = AlertDialog(
            title=Text("Change Password"),
            content=Column(
                controls=[old_pass, new_pass, confirm_pass],
                tight=True,
                spacing=10,
            ),
            actions=[
                TextButton("Cancel", on_click=lambda e: self.close_dialog()),
                ElevatedButton("Change", on_click=confirm_change),
            ],
        )
        
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()
        
    def close_dialog(self):
        """Close the current dialog"""
        self.page.dialog.open = False
        self.page.update()
        
    async def show_dialog(self, title: str, message: str):
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
        
    def view_detection_details(self, detection: Dict):
        """View detailed detection results"""
        # Implement detailed view
        pass
        
    def logout(self):
        """Logout user"""
        if self.auth.is_authenticated():
            self.auth.logout()
            self.clear_session()
            
    # =====================================================================
    # DATA HELPERS
    # =====================================================================
    
    def get_dashboard_stats(self) -> Dict:
        """Get statistics for dashboard"""
        try:
            if not self.auth.is_authenticated():
                return self.get_empty_stats()
                
            # Get detection history for user
            history = self.db.get_detection_history(self.auth.current_user['id'], limit=100)
            
            total_detections = len(history)
            anomalies_found = sum(h.get('anomalies_detected', 0) for h in history)
            models = self.db.get_user_models(self.auth.current_user['id'])
            
            # Get recent anomalies
            recent_anomalies = self.db.get_user_anomalies(self.auth.current_user['id'], 7)
            
            return {
                "total_detections": str(total_detections),
                "anomalies_found": str(anomalies_found),
                "models_trained": str(len(models)),
                "uptime": "24h",  # Placeholder
                "recent_anomalies": recent_anomalies,
                "detection_history": [],
            }
            
        except Exception as e:
            print(f"Error getting dashboard stats: {e}")
            return self.get_empty_stats()
            
    def get_empty_stats(self) -> Dict:
        """Return empty statistics"""
        return {
            "total_detections": "0",
            "anomalies_found": "0",
            "models_trained": "0",
            "uptime": "N/A",
            "recent_anomalies": [],
            "detection_history": [],
        }
            
    def get_user_models(self) -> List[Dict]:
        """Get user's models"""
        try:
            if not self.auth.is_authenticated():
                return []
                
            models = self.db.get_user_models(self.auth.current_user['id'])
            return [dict(m) for m in models]
            
        except Exception as e:
            print(f"Error getting models: {e}")
            return []
            
    def get_detection_history(self) -> List[Dict]:
        """Get detection history"""
        try:
            if not self.auth.is_authenticated():
                return []
                
            history = self.db.get_detection_history(self.auth.current_user['id'], limit=100)
            return [dict(h) for h in history]
            
        except Exception as e:
            print(f"Error getting history: {e}")
            return []
            
    def calculate_severity(self, confidence: float) -> str:
        """Calculate severity based on confidence"""
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
            
    # =====================================================================
    # SESSION MANAGEMENT
    # =====================================================================
    
    def load_session(self):
        """Load session from file"""
        if self.session_file.exists():
            try:
                with open(self.session_file, 'r') as f:
                    session_data = json.load(f)
                    
                session_token = session_data.get('session_token')
                if session_token and self.auth.validate_session(session_token):
                    print(f"Session loaded for {self.auth.current_user['username']}")
            except Exception as e:
                print(f"Could not load session: {e}")
                
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
                    # Handle result
                    
                await asyncio.sleep(0.1)
                
            except Exception as e:
                print(f"Error in task processor: {e}")
                await asyncio.sleep(1)


# =====================================================================
# UTILITY CLASSES
# =====================================================================

class ListTile(ft.Row):
    """Custom list tile"""
    
    def __init__(self, leading=None, title=None, subtitle=None, trailing=None, **kwargs):
        super().__init__(**kwargs)
        
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
            
        self.controls = controls
        self.vertical_alignment = CrossAxisAlignment.CENTER
        self.spacing = 10


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
    except ImportError:
        print("Error: flet is not installed.")
        print("Please install it with: pip install flet")
        sys.exit(1)
        
    # Run the app
    ft.app(target=main)