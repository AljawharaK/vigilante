# intrusion_detection/utils.py
import os
import json
import pandas as pd
from datetime import datetime, timedelta
from typing import Tuple, Optional, Dict, Any, List
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from rich.console import Console
import sys
from pathlib import Path
import re
import hashlib

# ========================
# Handle optional filetype library for MIME type detection
# ========================
try:
    import filetype
    _filetype_available = True
except ImportError:
    print("⚠️ filetype not installed. Installing recommended: pip install filetype")
    _filetype_available = False

console = Console()

# ========================
# SECURITY: Session Encryption & Management
# ========================

class SecureSessionManager:
    """Handle secure session storage with simpler cryptography (no external deps)"""
    
    # Session file path
    SESSION_FILE = Path.home() / ".vigilante_session"
    
    @classmethod
    def _derive_key_from_system(cls) -> str:
        """
        Derive a unique key from system-specific values
        
        Returns:
            Derived key string
        """
        import platform
        import getpass
        
        # Combine system identifiers
        system_info = f"{platform.node()}{platform.system()}{platform.machine()}{getpass.getuser()}"
        
        # Create a hash that will be consistent for this installation
        key_hash = hashlib.sha256(system_info.encode()).hexdigest()
        
        # Also use a salt file for additional security
        salt_path = Path.home() / ".vigilante_salt"
        
        if salt_path.exists():
            with open(salt_path, 'rb') as f:
                salt = f.read()
        else:
            salt = os.urandom(32)
            with open(salt_path, 'wb') as f:
                f.write(salt)
        
        # Combine with salt
        combined = key_hash + salt.hex()
        return hashlib.sha256(combined.encode()).hexdigest()[:32]
    
    @classmethod
    def _simple_encrypt(cls, data: str, key: str) -> str:
        """
        Simple XOR-based encryption (for session data only - not for sensitive passwords)
        
        Args:
            data: String to encrypt
            key: Encryption key
            
        Returns:
            Encrypted string (hex encoded)
        """
        import itertools
        
        # Convert to bytes
        data_bytes = data.encode('utf-8')
        key_bytes = key.encode('utf-8')
        
        # XOR encryption
        encrypted = bytes([a ^ b for a, b in zip(data_bytes, itertools.cycle(key_bytes))])
        
        # Return hex encoded
        return encrypted.hex()
    
    @classmethod
    def _simple_decrypt(cls, encrypted_hex: str, key: str) -> str:
        """
        Simple XOR-based decryption
        
        Args:
            encrypted_hex: Hex encoded encrypted string
            key: Encryption key
            
        Returns:
            Decrypted string
        """
        import itertools
        
        # Convert from hex
        encrypted = bytes.fromhex(encrypted_hex)
        key_bytes = key.encode('utf-8')
        
        # XOR decryption (same as encryption)
        decrypted = bytes([a ^ b for a, b in zip(encrypted, itertools.cycle(key_bytes))])
        
        return decrypted.decode('utf-8')
    
    @classmethod
    def _calculate_signature(cls, session_token: str, username: str, saved_at: str) -> str:
        """
        Calculate signature for session integrity verification
        
        Args:
            session_token: Session token
            username: Username
            saved_at: Timestamp when saved
            
        Returns:
            Signature hash
        """
        data = f"{session_token}:{username}:{saved_at}".encode()
        return hashlib.sha256(data).hexdigest()[:32]
    
    @classmethod
    def save_session_secure(cls, session_token: str, username: str) -> bool:
        """
        Securely save session with encryption and integrity checking
        
        Args:
            session_token: Session token to save
            username: Username associated with session
            
        Returns:
            True if saved successfully, False otherwise
        """
        try:
            session_data = {
                'session_token': session_token,
                'username': username,
                'saved_at': datetime.now().isoformat(),
                'version': '2.0',
            }
            
            # Add signature for integrity
            session_data['signature'] = cls._calculate_signature(
                session_token, username, session_data['saved_at']
            )
            
            # Convert to JSON
            json_data = json.dumps(session_data)
            
            # Encrypt
            key = cls._derive_key_from_system()
            encrypted = cls._simple_encrypt(json_data, key)
            
            # Save with restricted permissions
            with open(cls.SESSION_FILE, 'w') as f:
                f.write(encrypted)
            
            # Set secure file permissions (read/write only for owner)
            os.chmod(cls.SESSION_FILE, 0o600)
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to save session securely: {e}")
            return False
    
    @classmethod
    def load_session_secure(cls) -> Optional[Dict[str, Any]]:
        """
        Load and decrypt session from disk
        
        Returns:
            Session dictionary if valid, None otherwise
        """
        if not cls.SESSION_FILE.exists():
            return None
        
        try:
            with open(cls.SESSION_FILE, 'r') as f:
                encrypted = f.read().strip()
            
            if not encrypted:
                return None
            
            # Decrypt
            key = cls._derive_key_from_system()
            json_data = cls._simple_decrypt(encrypted, key)
            
            # Parse JSON
            session_data = json.loads(json_data)
            
            # Validate session structure
            if not all(k in session_data for k in ['session_token', 'username', 'saved_at', 'signature']):
                return None
            
            # Verify signature
            expected_signature = cls._calculate_signature(
                session_data['session_token'],
                session_data['username'],
                session_data['saved_at']
            )
            
            if session_data.get('signature') != expected_signature:
                return None
            
            # Check if session is expired (24 hours default)
            saved_at = datetime.fromisoformat(session_data['saved_at'])
            if datetime.now() - saved_at > timedelta(hours=24):
                cls.clear_session_secure()
                return None
            
            return session_data
            
        except Exception as e:
            print(f"⚠️ Failed to load session: {e}")
            return None
    
    @classmethod
    def clear_session_secure(cls) -> bool:
        """
        Securely delete session file
        
        Returns:
            True if cleared successfully
        """
        try:
            if cls.SESSION_FILE.exists():
                # Overwrite with random data before deletion
                size = cls.SESSION_FILE.stat().st_size
                with open(cls.SESSION_FILE, 'wb') as f:
                    f.write(os.urandom(size))
                
                # Delete the file
                cls.SESSION_FILE.unlink()
            
            return True
            
        except Exception as e:
            print(f"⚠️ Failed to clear session: {e}")
            return False
    
    @classmethod
    def rotate_session_keys(cls) -> bool:
        """
        Rotate encryption keys and re-encrypt existing session if present
        
        Returns:
            True if rotation successful
        """
        try:
            # Load existing session if any
            session_data = cls.load_session_secure()
            
            if session_data:
                # Delete old salt to force new key derivation
                salt_path = Path.home() / ".vigilante_salt"
                if salt_path.exists():
                    salt_path.unlink()
                
                # Re-save with new key
                return cls.save_session_secure(
                    session_data['session_token'],
                    session_data['username']
                )
            
            return True
            
        except Exception as e:
            print(f"⚠️ Key rotation failed: {e}")
            return False


class SessionInvalidator:
    """Handle session invalidation on security events"""
    
    @classmethod
    def invalidate_on_password_change(cls, user_id: int, db_manager, auth_manager) -> bool:
        """
        Invalidate all sessions when password is changed
        
        Args:
            user_id: User ID whose password changed
            db_manager: Database manager instance
            auth_manager: Auth manager instance
            
        Returns:
            True if invalidation successful
        """
        try:
            # Invalidate all database sessions for this user
            count = db_manager.invalidate_user_sessions(user_id)
            
            # Clear local session file if it belongs to this user
            session_data = SecureSessionManager.load_session_secure()
            if session_data and auth_manager.current_user and session_data.get('username') == auth_manager.current_user.get('username'):
                SecureSessionManager.clear_session_secure()
            
            # Log the invalidation
            db_manager.log_audit_event(
                user_id=user_id,
                username=auth_manager.current_user.get('username', 'unknown') if auth_manager.current_user else 'unknown',
                action="session_invalidation",
                resource="all_sessions",
                status="success",
                details={"reason": "password_change", "sessions_invalidated": count}
            )
            
            print(f"✅ Invalidated {count} sessions for user {user_id}")
            return True
            
        except Exception as e:
            print(f"❌ Session invalidation failed: {e}")
            return False
    
    @classmethod
    def invalidate_on_role_change(cls, user_id: int, db_manager, auth_manager) -> bool:
        """
        Invalidate sessions when user role changes
        
        Args:
            user_id: User ID whose role changed
            db_manager: Database manager instance
            auth_manager: Auth manager instance
            
        Returns:
            True if invalidation successful
        """
        try:
            # Invalidate all sessions for this user
            count = db_manager.invalidate_user_sessions(user_id)
            
            # Clear local session if it's the current user
            if auth_manager.current_user and user_id == auth_manager.current_user.get('id'):
                SecureSessionManager.clear_session_secure()
            
            # Log the invalidation
            db_manager.log_audit_event(
                user_id=auth_manager.current_user.get('id', user_id) if auth_manager.current_user else user_id,
                username=auth_manager.current_user.get('username', 'system') if auth_manager.current_user else 'system',
                action="session_invalidation",
                resource="user_sessions",
                status="success",
                details={"user_id": user_id, "reason": "role_change", "sessions_invalidated": count}
            )
            
            print(f"✅ Invalidated {count} sessions for role change")
            return True
            
        except Exception as e:
            print(f"❌ Session invalidation on role change failed: {e}")
            return False
    
    @classmethod
    def invalidate_on_user_deactivation(cls, user_id: int, db_manager) -> bool:
        """
        Invalidate sessions when user is deactivated
        
        Args:
            user_id: User ID being deactivated
            db_manager: Database manager instance
            
        Returns:
            True if invalidation successful
        """
        try:
            count = db_manager.invalidate_user_sessions(user_id)
            print(f"✅ Invalidated {count} sessions for deactivated user {user_id}")
            return True
            
        except Exception as e:
            print(f"❌ Session invalidation on deactivation failed: {e}")
            return False


# ========================
# SECURITY: Input Validation
# ========================
        
class SecurityValidator:
    """Handle security validation and attack prevention"""
    
    # Allowed file extensions for input files
    ALLOWED_EXTENSIONS = {'.csv', '.json'}
    
    # Maximum file size (100MB to prevent DoS)
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
    
    # Maximum rows for processing (prevent memory DoS)
    MAX_ROWS = 10_000_000  # 10 million rows max
    
    # Dangerous patterns to sanitize
    DANGEROUS_PATTERNS = [
        r'<script.*?>.*?</script>',  # XSS
        r'javascript:',               # JavaScript injection
        r'vbscript:',                # VBScript injection
        r'onload=',                  # Event handler injection
        r'onerror=',                 # Event handler injection
        r'<\?php',                   # PHP code injection
        r'eval\s*\(',                # Code evaluation
        r'system\s*\(',              # System command
        r'exec\s*\(',                # Command execution
        r'passthru\s*\(',            # PHP passthru
        r'shell_exec\s*\(',          # Shell execution
        r'base64_decode\s*\(',       # Base64 decode (potential obfuscation)
        r'\\\\x[0-9a-fA-F]{2}',      # Hex encoded chars (if escaped)
    ]
    
    @classmethod
    def _detect_file_mime_type(cls, file_path: str) -> Optional[str]:
        """
        Detect file MIME type using filetype library (pure Python, no dependencies)
        
        Args:
            file_path: Path to the file
            
        Returns:
            MIME type string or None if detection fails
        """
        if not _filetype_available:
            return None
        
        try:
            # Guess the file type using magic bytes
            kind = filetype.guess(file_path)
            if kind is not None:
                return kind.mime
            return None
        except Exception as e:
            print(f"⚠️ File type detection failed: {e}")
            return None
    
    @classmethod
    def validate_file_input(cls, file_path: str) -> Tuple[bool, str]:
        """
        Validate input file for security threats
        
        Args:
            file_path: Path to the input file
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if file exists
        if not os.path.exists(file_path):
            return False, f"File not found: {file_path}"
        
        # Get file size
        try:
            file_size = os.path.getsize(file_path)
            if file_size > cls.MAX_FILE_SIZE:
                return False, f"File too large: {file_size / (1024*1024):.2f} MB exceeds {cls.MAX_FILE_SIZE / (1024*1024):.0f} MB limit"
            
            if file_size == 0:
                return False, "Empty file provided"
        except OSError as e:
            return False, f"Cannot access file: {str(e)}"
        
        # Check file extension
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext not in cls.ALLOWED_EXTENSIONS:
            return False, f"Invalid file extension '{file_ext}'. Allowed: {', '.join(cls.ALLOWED_EXTENSIONS)}"
        
        # Check file content using filetype (magic bytes detection)
        mime = cls._detect_file_mime_type(file_path)
        
        if mime:
            allowed_mime_types = [
                'text/csv', 'text/plain', 'application/csv',
                'application/json', 'text/json', 'application/octet-stream',
                'text/x-csv', 'text/x-json'
            ]
            
            if mime not in allowed_mime_types:
                # For CSV files, sometimes filetype detects as text/plain which is fine
                if file_ext == '.csv' and mime == 'text/plain':
                    pass  # Accept text/plain as valid for CSV
                elif file_ext == '.json' and mime == 'text/plain':
                    pass  # Accept text/plain as valid for JSON
                else:
                    return False, f"Suspicious file type detected: {mime}"
        
        return True, "OK"
    
    @classmethod
    def validate_csv_content(cls, file_path: str, sample_rows: int = 1000) -> Tuple[bool, str, Optional[pd.DataFrame]]:
        """
        Validate CSV file content for security threats and DoS attacks in
        NETWORK DATASETS (e.g., flow durations in microseconds, total bytes)
        
        Args:
            file_path: Path to CSV file
            sample_rows: Number of rows to sample for validation
            
        Returns:
            Tuple of (is_valid, error_message, dataframe_preview)
        """
        import pandas as pd
        
        try:
            # First, check number of rows without loading full file
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                row_count = sum(1 for _ in f) - 1  # Subtract header
                
                if row_count > cls.MAX_ROWS:
                    return False, f"File contains {row_count:,} rows exceeding limit of {cls.MAX_ROWS:,} rows", None
            
            # Try to read with security checks
            df_preview = pd.read_csv(file_path, nrows=sample_rows)
            
            # Check for empty dataframe
            if df_preview.empty:
                return False, "CSV file contains no data", None
            
            # Check for suspicious column names
            suspicious_columns = []
            for col in df_preview.columns:
                col_lower = col.lower()
                # Check for SQL injection patterns in column names
                sql_patterns = ['select', 'insert', 'update', 'delete', 'drop', 'alter', 'create', 'exec', 'union']
                for pattern in sql_patterns:
                    if pattern in col_lower:
                        suspicious_columns.append(col)
                        break
            
            if suspicious_columns:
                print(f"⚠️ Warning: Suspicious column names detected: {suspicious_columns}")
            
            # Check for encoding issues
            problematic_chars = []
            for col in df_preview.select_dtypes(include=['object']).columns:
                sample = df_preview[col].dropna().head(10)
                for val in sample:
                    if isinstance(val, str):
                        # Check for null bytes
                        if '\x00' in val:
                            problematic_chars.append(f"Null byte in column '{col}'")
            
            if problematic_chars:
                print(f"⚠️ Warning: {len(problematic_chars)} encoding issues detected")
            
            return True, "OK", df_preview
            
        except pd.errors.EmptyDataError:
            return False, "CSV file is empty", None
        except pd.errors.ParserError as e:
            return False, f"CSV parsing error: {str(e)}", None
        except UnicodeDecodeError as e:
            return False, f"File encoding error: {str(e)}. Try UTF-8 encoding", None
        except Exception as e:
            return False, f"Error reading CSV: {str(e)}", None
    
    @classmethod
    def validate_json_content(cls, file_path: str) -> Tuple[bool, str, Optional[Dict]]:
        """
        Validate JSON file content for security threats in
        NETWORK DATASETS (e.g., flow durations in microseconds, total bytes)
        
        Args:
            file_path: Path to JSON file
            
        Returns:
            Tuple of (is_valid, error_message, json_data)
        """
        import json
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Check for suspicious patterns in raw content
                for pattern in cls.DANGEROUS_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        return False, f"Suspicious pattern detected in JSON: {pattern[:50]}", None
                
                # Parse JSON
                data = json.loads(content)
                
                # Check for deeply nested structures (DoS prevention)
                def check_nesting(obj, depth=0, max_depth=50):  # Increased max_depth for network datasets
                    """Check for excessive nesting that could cause DoS"""
                    if depth > max_depth:
                        return False
                    if isinstance(obj, dict):
                        return all(check_nesting(v, depth + 1, max_depth) for v in obj.values())
                    elif isinstance(obj, list):
                        return all(check_nesting(item, depth + 1, max_depth) for item in obj)
                    return True
                
                if not check_nesting(data):
                    return False, "JSON structure too deeply nested (potential DoS)", None
                
                return True, "OK", data
                
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON format at line {e.lineno}, column {e.colno}: {str(e)}", None
        except UnicodeDecodeError as e:
            return False, f"File encoding error: {str(e)}. Try UTF-8 encoding", None
        except MemoryError:
            return False, "JSON file too large to parse in memory", None
        except Exception as e:
            return False, f"Error reading JSON: {str(e)}", None

    @classmethod
    def rate_limit_check(cls, user_id: int, action: str, db_connection, max_requests: int = 70, time_window: int = 60) -> Tuple[bool, int]:
        """
        Check rate limiting for user actions to prevent brute force attacks
        
        Args:
            user_id: User ID
            action: Action being performed (e.g., 'detect', 'train')
            db_connection: Database connection for logging
            max_requests: Maximum allowed requests in time window
            time_window: Time window in seconds
            
        Returns:
            Tuple of (is_allowed, remaining_requests)
        """
        from datetime import datetime, timedelta
        
        try:
            # Get recent requests count from audit logs
            cutoff_time = datetime.now() - timedelta(seconds=time_window)
            
            with db_connection.conn.cursor() as cursor:
                cursor.execute("""
                    SELECT COUNT(*) FROM audit_logs 
                    WHERE user_id = %s 
                    AND action = %s 
                    AND created_at >= %s
                """, (user_id, action, cutoff_time))
                
                count = cursor.fetchone()[0]
                
                remaining = max_requests - count
                is_allowed = count < max_requests
                
                if not is_allowed:
                    print(f"⚠️ Rate limit exceeded for user {user_id}: {count}/{max_requests} requests in {time_window}s")
                
                return is_allowed, max(0, remaining)
                
        except Exception as e:
            print(f"⚠️ Rate limit check failed: {e}")
            return True, max_requests  # Allow on error

# ========================
# Administrator System Report Generation
# ========================
    
# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def resolve_logo_path() -> str:
    """Resolve the path to Vigilante_logo.png - checks root directory first"""
    
    # Get the project root directory (where setup.py is located)
    # Current file is in intrusion_detection/utils.py, so go up 1 level
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
    return None

def generate_pdf_report(report_data: Dict[str, Any], output_path: str):
    """Generate PDF report for system statistics with logo, models, and anomalies"""
    
    from PIL import Image as PILImage
    from reportlab.platypus import Image as ReportLabImage
    
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
    logo_path = resolve_logo_path()
    
    # Add logo centered (without using tables)
    if logo_path and os.path.exists(logo_path):
        try:
            # Open with PIL to get dimensions
            img = PILImage.open(logo_path)
            img_width, img_height = img.size
            
            # Target logo height of 60 points
            target_height = 60
            scale = target_height / img_height
            scaled_width = img_width * scale
            scaled_height = img_height * scale
            
            # Ensure width doesn't exceed 100 points
            if scaled_width > 100:
                scale = 100 / img_width
                scaled_width = img_width * scale
                scaled_height = img_height * scale
            
            # Create logo
            logo_obj = ReportLabImage(logo_path, width=scaled_width, height=scaled_height)
            
            # Center the logo by using a 1-row, 3-column table with empty cells on sides
            logo_table = Table([[Spacer(1, 1), logo_obj, Spacer(1, 1)]], colWidths=[doc.width/2 - scaled_width/2, scaled_width, doc.width/2 - scaled_width/2])
            logo_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (0, 0), 'RIGHT'),
                ('ALIGN', (1, 0), (1, 0), 'CENTER'),
                ('ALIGN', (2, 0), (2, 0), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(logo_table)
            story.append(Spacer(1, 10))
            
        except Exception as e:
            print(f"Warning: Could not load logo: {e}")
            import traceback
            traceback.print_exc()
    else:
        print(f"Logo file not found at: {logo_path}")
        story.append(Spacer(1, 30))
    
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
    
    title_box = Table(title_cell_data, colWidths=[430])
    title_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), NAVY_BLUE),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('LEFTPADDING', (0, 0), (-1, -1), 20),
        ('RIGHTPADDING', (0, 0), (-1, -1), 20),
    ]))
    
    story.append(title_box)
    story.append(Spacer(1, 20))
    
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
    
    detection_table = Table(detection_data, colWidths=[215, 215])
    detection_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), NAVY_BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), LILAC_PURPLE),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(detection_table)
    story.append(Spacer(1, 20))
    
    # Models in System
    story.append(Paragraph("Models in System", styles['Heading2']))
    
    all_models = report_data.get('all_models', [])
    if all_models:
        model_data = [["ID", "Name", "User", "Type", "Accuracy", "Samples", "Created"]]
        
        for model in all_models:
            if model:
                name = model.get('name', 'N/A')
                display_name = name[:20] + "..." if len(name) > 25 else name
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
        
        model_table = Table(model_data, colWidths=[40, 110, 60, 90, 60, 60, 80])
        model_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_BLUE),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), LILAC_PURPLE),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 8)
        ]))
        story.append(model_table)
    else:
        story.append(Paragraph("No models found in the system.", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # User Logs
    story.append(Paragraph("User Logs", styles['Heading2']))
    
    user_logs = report_data.get('user_logs', [])
    if user_logs:
        log_data = [["ID", "Timestamp", "User", "Action", "Resource", "Status"]]
        
        for log in user_logs:
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
        
        log_table = Table(log_data, colWidths=[40, 100, 80, 80, 100, 50])
        
        table_style = [
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_BLUE),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), LILAC_PURPLE),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
        ]
        
        log_table.setStyle(TableStyle(table_style))
        story.append(log_table)
        story.append(Spacer(1, 5))
        story.append(Paragraph(f"Showing {min(20, len(user_logs))} of {len(user_logs)} logs", 
                              ParagraphStyle('Footnote', parent=styles['Normal'], fontSize=8, textColor=colors.gray)))
    else:
        story.append(Paragraph("No user logs found for the specified period.", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # All Anomalies
    story.append(Paragraph("All Detected Anomalies", styles['Heading2']))
    story.append(Paragraph("Complete list of all anomalies detected during the report period", 
                          ParagraphStyle('Subheading', parent=styles['Normal'], fontSize=10, textColor=colors.gray)))
    story.append(Spacer(1, 10))

    # Correct way to access total_anomalies_detected
    detection_summary = report_data.get('detection_summary', {})
    total_anomalies = detection_summary.get('total_anomalies_detected', 0)

    anomalies = report_data.get('all_anomalies', [])
    if anomalies:
        # Define anomaly table columns
        anomaly_headers = [["Detected At", "Flow ID", "Confidence", "Severity"]]
        
        # Calculate how many pages we need (30 anomalies per page)
        ANOMALIES_PER_PAGE = 30
        total_anomaly_count = len(anomalies)
        total_pages = (total_anomaly_count + ANOMALIES_PER_PAGE - 1) // ANOMALIES_PER_PAGE
        
        # Add a note about pagination at the beginning
        if total_pages > 1:
            story.append(Paragraph(
                f"Total anomalies: {total_anomaly_count:,} (split across {total_pages} pages, {ANOMALIES_PER_PAGE} per page)",
                ParagraphStyle('PaginationNote', parent=styles['Normal'], fontSize=9, 
                              textColor=colors.darkblue, alignment=1)
            ))
            story.append(Spacer(1, 10))
        
        # Process anomalies in batches
        for page_num in range(total_pages):
            start_idx = page_num * ANOMALIES_PER_PAGE
            end_idx = min(start_idx + ANOMALIES_PER_PAGE, total_anomaly_count)
            page_anomalies = anomalies[start_idx:end_idx]
            
            # Build table data for this page
            anomaly_data = anomaly_headers.copy()  # Start with headers
            
            for anomaly in page_anomalies:
                if anomaly:
                    detected_at = anomaly.get('detected_at')
                    if detected_at and hasattr(detected_at, 'strftime'):
                        detected_str = detected_at.strftime('%Y-%m-%d %H:%M')
                    else:
                        detected_str = str(detected_at) if detected_at else 'N/A'
                    
                    confidence = anomaly.get('confidence', 0)
                    confidence_str = f"{confidence:.4f}" if confidence is not None else "0.0000"
                    severity = anomaly.get('severity', 'Medium')
                    flow_id = anomaly.get('index', anomaly.get('flow_id', 'N/A'))
                    
                    anomaly_data.append([
                        detected_str,
                        str(flow_id),
                        confidence_str,
                        severity
                    ])
            
            # Create table for this page
            anomaly_table = Table(anomaly_data, colWidths=[130, 100, 100, 100])
            anomaly_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), NAVY_BLUE),
                ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('TOPPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), LILAC_PURPLE),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [LILAC_PURPLE, colors.whitesmoke]),
            ]))
            
            story.append(anomaly_table)
            story.append(Spacer(1, 10))
            
            # Add page number footer for this page's anomalies
            page_info = f"Page {page_num + 1} of {total_pages} - Anomalies {start_idx + 1} to {end_idx} of {total_anomaly_count}"
            story.append(Paragraph(
                page_info,
                ParagraphStyle('PageInfo', parent=styles['Normal'], fontSize=8, 
                              textColor=colors.gray, alignment=1)
            ))
            
            # Add page break if not the last page
            if page_num < total_pages - 1:
                story.append(PageBreak())
        
        # Add final summary
        story.append(Spacer(1, 5))
        story.append(Paragraph(
            f"Showing all {total_anomaly_count} of {total_anomaly_count:,} anomalies across {total_pages} pages",
            ParagraphStyle('FinalSummary', parent=styles['Normal'], fontSize=9, 
                          textColor=colors.green, alignment=1)
        ))
        
    else:
        story.append(Paragraph("No anomalies detected in the period.", styles['Normal']))

    # Footer
    story.append(Spacer(1, 40))
    footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, alignment=1, textColor=colors.gray)
    story.append(Paragraph("Confidential - For authorized personnel only", footer_style))
    
    # Build PDF
    doc.build(story)
    
    return output_path

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