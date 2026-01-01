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

console = Console()

def generate_pdf_report(report_data: Dict[str, Any], output_path: str):
    """Generate PDF report for system statistics - simplified roles"""
    
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
    
    # Title with simplified role mention
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1,
        textColor=colors.HexColor('#1a237e')  # Dark blue
    )
    
    story.append(Paragraph("Vigilante Security - System Report", title_style))
    story.append(Paragraph("Administrator Report - Role-Based Access System", 
                          ParagraphStyle('Subtitle', parent=styles['Heading3'], alignment=1)))
    
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
        ["Total Anomalies Detected", detection_summary.get('total_anomalies_detected', 0)],
        ["Avg False Positive Rate", f"{detection_summary.get('avg_false_positive_rate', 0):.2f}%"],
        ["Predominant Severity", detection_summary.get('predominant_severity', 'Low')]
    ]
    
    detection_table = Table(detection_data)
    detection_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(detection_table)
    story.append(Spacer(1, 20))
    
    # User Activity
    story.append(Paragraph("User Activity", styles['Heading2']))
    
    user_activity = report_data.get('user_activity', {})
    activity_data = [
        ["Activity", "Count"],
        ["Total Logins", user_activity.get('total_logins', 0)],
        ["Models Trained", user_activity.get('models_trained', 0)],
        ["Detection Jobs Run", user_activity.get('detection_jobs_run', 0)]
    ]
    
    activity_table = Table(activity_data)
    activity_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(activity_table)
    story.append(Spacer(1, 20))
    
    # Recent Anomalies
    story.append(Paragraph("Recent Anomalies", styles['Heading2']))
    
    anomalies = report_data.get('recent_anomalies', [])
    if anomalies:
        anomaly_data = [["Flow ID", "Source IP", "Destination IP", "Confidence", "Severity"]]
        
        for anomaly in anomalies[:10]:  # Show top 10
            anomaly_data.append([
                anomaly.get('flow_id', 'N/A'),
                anomaly.get('src_ip', 'N/A'),
                anomaly.get('dst_ip', 'N/A'),
                f"{anomaly.get('confidence_score', 0):.2f}",
                anomaly.get('severity', 'Medium')
            ])
        
        anomaly_table = Table(anomaly_data, colWidths=[1*inch, 1.5*inch, 1.5*inch, 1*inch, 1*inch])
        anomaly_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('FONTSIZE', (0, 1), (-1, -1), 8)
        ]))
        story.append(anomaly_table)
    else:
        story.append(Paragraph("No anomalies detected in the period.", styles['Normal']))
    
    # Footer
    story.append(Spacer(1, 40))
    story.append(Paragraph("Confidential - For authorized personnel only", 
                          ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, alignment=1)))
    
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
        "torch_version": torch.__version__,
        "cuda_available": torch.cuda.is_available(),
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