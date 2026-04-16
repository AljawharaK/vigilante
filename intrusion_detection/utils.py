# intrusion_detection/utils.py
import os
import json
import pandas as pd
from datetime import datetime
from typing import Dict, Any, List
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from rich.table import Table as RichTable
from rich.console import Console
import os
import sys
from importlib import resources
from pathlib import Path

console = Console()

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def _resolve_logo_path() -> str:
    """Resolve the path to Vigilante_logo.png"""
    # Method 1: Check in the same directory as this file
    current_dir = Path(__file__).parent
    local_path = current_dir / 'assets' / 'Vigilante_logo.png'
    print(f"Checking logo path 1: {local_path} - Exists: {local_path.exists()}")
    if local_path.exists():
        return str(local_path)
    
    # Method 2: Check in the parent directory's assets
    parent_dir = current_dir.parent
    parent_assets_path = parent_dir / 'assets' / 'Vigilante_logo.png'
    print(f"Checking logo path 2: {parent_assets_path} - Exists: {parent_assets_path.exists()}")
    if parent_assets_path.exists():
        return str(parent_assets_path)
    
    # Method 3: Check in current working directory
    cwd_path = Path.cwd() / 'assets' / 'Vigilante_logo.png'
    print(f"Checking logo path 3: {cwd_path} - Exists: {cwd_path.exists()}")
    if cwd_path.exists():
        return str(cwd_path)
    
    # Method 4: Try to find using package resources
    try:
        from importlib import resources
        package_asset = resources.files(__package__).joinpath('assets', 'Vigilante_logo.png')
        print(f"Checking package resource: {package_asset}")
        if package_asset and hasattr(package_asset, 'exists') and package_asset.exists():
            return str(package_asset)
    except Exception as e:
        print(f"Package resource lookup failed: {e}")
    
    print(f"Logo not found in any location. Logo will not be displayed.")
    return None

def generate_pdf_report(report_data: Dict[str, Any], output_path: str):
    """Generate PDF report for system statistics with logo, models, and anomalies"""
    
    from reportlab.lib.utils import ImageReader
    from PIL import Image
    
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )
    
    styles = getSampleStyleSheet()
    story = []
    
    # Define custom colors
    LILAC_PURPLE = colors.HexColor("#BFA7F3")
    NAVY_BLUE = colors.HexColor("#3E346D")
    WHITE = colors.white
    
    # Try to load and add logo
    logo_path = _resolve_logo_path()
    print(f"Logo path resolved to: {logo_path}")
    
    # Create header with logo and title in navy box
    header_content = []
    
    # Add logo if available
    logo_obj = None
    if logo_path and os.path.exists(logo_path):
        try:
            from reportlab.platypus import Image
            img = Image.open(logo_path)
            img_width, img_height = img.size
            print(f"Logo loaded: {img_width}x{img_height}")
            
            # Target logo height of 50 points
            target_height = 50
            scale = target_height / img_height
            scaled_width = img_width * scale
            scaled_height = img_height * scale
            
            # Ensure width doesn't exceed 80 points
            if scaled_width > 80:
                scale = 80 / img_width
                scaled_width = img_width * scale
                scaled_height = img_height * scale
            
            logo_obj = Image(logo_path, width=scaled_width, height=scaled_height)
            print(f"Logo scaled to: {scaled_width}x{scaled_height}")
        except Exception as e:
            print(f"Warning: Could not load logo: {e}")
            import traceback
            traceback.print_exc()
    else:
        print(f"Logo not found at: {logo_path}")
    
    # Title with navy background box (smaller font)
    title_style = ParagraphStyle(
        'TitleInBox', 
        parent=styles['Heading1'], 
        fontSize=16,
        spaceAfter=3,
        textColor=WHITE,
        alignment=1,  # Center alignment
        fontName='Helvetica-Bold'
    )
    
    # Create title text
    title_text = "Vigilante - Administrator System Report"
    
    # Create a single cell table with navy background for the title section
    title_cell_data = [[
        Paragraph(title_text, title_style),
    ]]
    
    title_box = Table(title_cell_data, colWidths=[380])
    title_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), NAVY_BLUE),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('LEFTPADDING', (0, 0), (-1, -1), 20),
        ('RIGHTPADDING', (0, 0), (-1, -1), 20),
    ]))
    
    # If logo exists, create a header with logo on left and title box on right
    if logo_obj:
        # Create a table with logo and title side by side
        header_table = Table([[logo_obj, title_box]], colWidths=[80, 370])
        header_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, 0), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (0, 0), 0),
            ('RIGHTPADDING', (0, 0), (0, 0), 10),
            ('BACKGROUND', (1, 0), (1, 0), NAVY_BLUE),  # Ensure title box background
        ]))
        story.append(header_table)
    else:
        # Just the title box if no logo
        story.append(title_box)
        print("No logo found - displaying title only")
    
    story.append(Spacer(1, 15))
    
    # Report period
    period = report_data.get('report_period', {})
    period_text = f"Report Period: {period.get('start', 'N/A')} to {period.get('end', 'N/A')}"
    story.append(Paragraph(period_text, styles['Normal']))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Detection Summary
    story.append(Paragraph("Detection Summary", styles['Heading2']))
    
    detection_summary = report_data.get('detection_summary', {})
    detection_data = [
        ["Metric", "Value"],
        ["Total Flows Analyzed", f"{detection_summary.get('total_flows_analyzed', 0):,}"],
        ["Total Anomalies Detected", f"{detection_summary.get('total_anomalies_detected', 0):,}"],
        ["Detection Rate", f"{detection_summary.get('detection_rate', 0):.2%}"],
    ]
    
    detection_table = Table(detection_data, colWidths=[200, 200])
    detection_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), NAVY_BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('TOPPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), LILAC_PURPLE),
        ('TEXTCOLOR', (0, 1), (-1, -1), WHITE),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(detection_table)
    story.append(Spacer(1, 20))
    
    # Models in System
    story.append(Paragraph("Models in System", styles['Heading2']))
    
    all_models = report_data.get('all_models', [])
    if all_models:
        model_data = [["ID", "Name", "User", "Type", "Accuracy", "Samples", "Created"]]
        
        for model in all_models[:15]:
            if model:
                name = model.get('name', 'N/A')
                display_name = name[:25] + "..." if len(name) > 25 else name
                accuracy = model.get('accuracy')
                accuracy_str = f"{accuracy:.2%}" if accuracy else "N/A"
                training_samples = model.get('training_samples', 0)
                samples_str = f"{training_samples:,}" if training_samples else "N/A"
                created_at = model.get('created_at')
                created_str = created_at.strftime('%Y-%m-%d') if created_at and hasattr(created_at, 'strftime') else 'N/A'
                model_data.append([
                    str(model.get('id', 'N/A')),
                    display_name,
                    model.get('username', 'N/A'),
                    model.get('model_type', 'rnsa_knn'),
                    accuracy_str,
                    samples_str,
                    created_str
                ])
        
        model_table = Table(model_data, colWidths=[40, 120, 80, 60, 60, 60, 80])
        
        # Build style with alternating row colors
        table_style = [
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_BLUE),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]
        
        # Add alternating row colors for data rows
        for i in range(1, len(model_data)):
            if i % 2 == 1:
                table_style.append(('BACKGROUND', (0, i), (-1, i), LILAC_PURPLE))
                table_style.append(('TEXTCOLOR', (0, i), (-1, i), WHITE))
            else:
                table_style.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor("#D4C4F0")))  # Slightly lighter lilac
                table_style.append(('TEXTCOLOR', (0, i), (-1, i), NAVY_BLUE))
            table_style.append(('FONTSIZE', (0, i), (-1, i), 8))
            table_style.append(('TOPPADDING', (0, i), (-1, i), 6))
            table_style.append(('BOTTOMPADDING', (0, i), (-1, i), 6))
        
        model_table.setStyle(TableStyle(table_style))
        story.append(model_table)
    else:
        story.append(Paragraph("No models found in the system.", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # User Logs
    story.append(Paragraph("User Logs", styles['Heading2']))
    
    user_logs = report_data.get('user_logs', [])
    if user_logs:
        log_data = [["ID", "Timestamp", "User", "Action", "Resource", "Status"]]
        
        for log in user_logs[:20]:
            if log:
                timestamp = log.get('created_at')
                if timestamp and hasattr(timestamp, 'strftime'):
                    timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    timestamp_str = str(timestamp)[:19] if timestamp else 'N/A'
                
                username = log.get('username') or 'System'
                resource = log.get('resource') or '-'
                if len(resource) > 25:
                    resource = resource[:22] + '...'
                
                status = log.get('status', 'success')
                
                log_data.append([
                    str(log.get('id', '')),
                    timestamp_str,
                    username,
                    log.get('action', ''),
                    resource,
                    status
                ])
        
        log_table = Table(log_data, colWidths=[40, 110, 80, 80, 100, 50])
        
        # Build style with alternating row colors
        table_style = [
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_BLUE),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]
        
        # Add alternating row colors for data rows
        for i in range(1, len(log_data)):
            if i % 2 == 1:
                table_style.append(('BACKGROUND', (0, i), (-1, i), LILAC_PURPLE))
                table_style.append(('TEXTCOLOR', (0, i), (-1, i), WHITE))
            else:
                table_style.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor("#D4C4F0")))
                table_style.append(('TEXTCOLOR', (0, i), (-1, i), NAVY_BLUE))
            table_style.append(('FONTSIZE', (0, i), (-1, i), 8))
            table_style.append(('TOPPADDING', (0, i), (-1, i), 6))
            table_style.append(('BOTTOMPADDING', (0, i), (-1, i), 6))
        
        log_table.setStyle(TableStyle(table_style))
        story.append(log_table)
        story.append(Spacer(1, 5))
        story.append(Paragraph(f"Showing {min(20, len(user_logs))} of {len(user_logs)} logs", 
                              ParagraphStyle('Footnote', parent=styles['Normal'], fontSize=8, textColor=colors.gray)))
    else:
        story.append(Paragraph("No user logs found for the specified period.", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Recent Anomalies
    story.append(Paragraph("Recent Anomalies", styles['Heading2']))
    
    anomalies = report_data.get('recent_anomalies', [])
    if anomalies:
        anomaly_data = [["Detected At", "Flow ID", "Confidence", "Severity"]]
        
        for anomaly in anomalies[:10]:
            if anomaly:
                detected_at = anomaly.get('detected_at')
                if detected_at and hasattr(detected_at, 'strftime'):
                    detected_str = detected_at.strftime('%Y-%m-%d %H:%M')
                else:
                    detected_str = str(detected_at) if detected_at else 'N/A'
                
                confidence = anomaly.get('confidence', 0)
                confidence_str = f"{confidence:.2f}" if confidence is not None else "0.00"
                severity = anomaly.get('severity', 'Medium')
                
                anomaly_data.append([
                    detected_str,
                    str(anomaly.get('index', 'N/A')),
                    confidence_str,
                    severity
                ])
        
        anomaly_table = Table(anomaly_data, colWidths=[120, 80, 80, 80])
        
        # Build style with alternating row colors
        table_style = [
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_BLUE),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]
        
        # Add alternating row colors for data rows
        for i in range(1, len(anomaly_data)):
            if i % 2 == 1:
                table_style.append(('BACKGROUND', (0, i), (-1, i), LILAC_PURPLE))
                table_style.append(('TEXTCOLOR', (0, i), (-1, i), WHITE))
            else:
                table_style.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor("#D4C4F0")))
                table_style.append(('TEXTCOLOR', (0, i), (-1, i), NAVY_BLUE))
            table_style.append(('FONTSIZE', (0, i), (-1, i), 9))
            table_style.append(('TOPPADDING', (0, i), (-1, i), 8))
            table_style.append(('BOTTOMPADDING', (0, i), (-1, i), 8))
        
        anomaly_table.setStyle(TableStyle(table_style))
        story.append(anomaly_table)
    else:
        story.append(Paragraph("No anomalies detected in the period.", styles['Normal']))
    
    # Footer
    story.append(Spacer(1, 40))
    footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, alignment=1, textColor=colors.gray)
    story.append(Paragraph("Confidential - For authorized personnel only", footer_style))
    
    # Build PDF
    doc.build(story)
    
    return output_path

def format_table(data: List[Dict], title: str = "") -> RichTable:
    """Format data as a rich table"""
    if not data:
        table = RichTable(title=title)
        table.add_column("No data", style="yellow")
        return table
    
    # Create table with columns from first data item
    table = RichTable(title=title, show_header=True, header_style="bold cyan")
    
    # Add columns
    for key in data[0].keys():
        table.add_column(str(key), style="green")
    
    # Add rows
    for item in data:
        table.add_row(*[str(item.get(key, '')) for key in data[0].keys()])
    
    return table

def get_system_info() -> Dict[str, Any]:
    """Get system information"""
    import platform
    import psutil
    import torch
    
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "python_version": platform.python_version(),
        "cpu_count": psutil.cpu_count(),
        "total_memory": f"{psutil.virtual_memory().total / (1024**3):.2f} GB",
        "available_memory": f"{psutil.virtual_memory().available / (1024**3):.2f} GB",
    }
    
    if torch.cuda.is_available():
        info["gpu_name"] = torch.cuda.get_device_name(0)
        info["gpu_memory"] = f"{torch.cuda.get_device_properties(0).total_memory / (1024**3):.2f} GB"
    
    return info

def save_detection_to_csv(results: Dict[str, Any], output_path: str):
    """Save detection results to CSV"""
    # Extract anomalies
    anomalies = results.get('anomalies', [])
    
    if not anomalies:
        # Create empty CSV with headers
        pd.DataFrame(columns=['flow_id', 'src_ip', 'dst_ip', 'confidence_score', 'severity']).to_csv(output_path, index=False)
    else:
        # Convert to DataFrame and save
        df = pd.DataFrame(anomalies)
        df.to_csv(output_path, index=False)
    
    return output_path

def json_serializable(obj):
    """Convert numpy and pandas objects to JSON serializable types"""
    import numpy as np
    import pandas as pd
    
    if isinstance(obj, dict):
        return {k: json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [json_serializable(v) for v in obj]
    elif isinstance(obj, tuple):
        return tuple(json_serializable(v) for v in obj)
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