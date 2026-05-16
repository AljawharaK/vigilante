# intrusion_detection/auth.py
import bcrypt
import secrets
import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import resend
from dotenv import load_dotenv

from .database import DatabaseManager

load_dotenv()

class AuthManager:
    """Handle user authentication and authorization with OTP support"""
    
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.current_user = None
        self.current_session = None
        self.current_role = None
        self.permissions = {}
        
        # Initialize Resend
        resend.api_key = os.getenv("RESEND_API_KEY")
        if not resend.api_key:
            raise ValueError("RESEND_API_KEY not found in environment variables")
    
        # Store email configuration
        self.from_email = os.getenv("RESEND_FROM_EMAIL")
        if not self.from_email:
            raise ValueError("RESEND_FROM_EMAIL not found in environment variables")

    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify a password against its hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except:
            return False
    
    def generate_otp(self) -> tuple:
        """Generate OTP code"""
        otp_code = str(secrets.randbelow(900000) + 100000)  # 6-digit code
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        return otp_code, expires_at
    
    def send_otp_email(self, email: str, otp_code: str, username: str):
        """Send OTP code to user's email"""
        try:
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Vigilante Security - OTP Verification</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background-color: #1a237e; color: white; padding: 20px; text-align: center; }}
                    .content {{ padding: 30px; background-color: #f9f9f9; }}
                    .otp-code {{ font-size: 32px; font-weight: bold; text-align: center; 
                                color: #1a237e; margin: 20px 0; padding: 15px; 
                                background-color: #e8eaf6; border-radius: 5px; }}
                    .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
                    .warning {{ color: #d32f2f; font-weight: bold; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Vigilante Security</h1>
                        <p>Intrusion Detection System</p>
                    </div>
                    <div class="content">
                        <h2>OTP Verification</h2>
                        <p>Hello {username},</p>
                        <p>You are attempting to log in to the Vigilante Intrusion Detection System.</p>
                        <p>Please use the following One-Time Password (OTP) to complete your login:</p>
                    
                        <div class="otp-code">{otp_code}</div>
                    
                        <p class="warning">⚠️ This OTP is valid for 10 minutes only.</p>
                        <p>If you did not request this login, please ignore this email and contact your system administrator immediately.</p>
                    
                        <p>Best regards,<br>The Vigilante Security Team</p>
                    </div>
                    <div class="footer">
                        <p>This is an automated message from Vigilante Security System.</p>
                        <p>© {datetime.now().year} Vigilante Security. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """
        
            from_address = f"Vigilante Security <{self.from_email}>"
        
            r = resend.Emails.send({
                "from": from_address,
                "to": email,
                "subject": "Vigilante Security - OTP Verification Code",
                "html": html_content
            })
        
            print(f"✅ OTP email sent to {email}")
            return True
        
        except Exception as e:
            print(f"❌ Failed to send OTP email: {e}")
            return False
    
    # intrusion_detection/auth.py

    def login(self, username: str, password: str) -> Dict[str, Any]:
        """Login user - Step 1: Verify credentials"""
        try:
            # Get user from database
            user = self.db.get_user(username)
            if not user:
                return {"success": False, "message": "Invalid username or password"}
            
            # Check if user is active
            if not user['is_active']:
                return {"success": False, "message": "Account is deactivated"}
            
            # Verify password
            if not self.verify_password(password, user['password_hash']):
                # Increment failed login attempts
                self.db.update_user_failed_attempts(user['id'])
                return {"success": False, "message": "Invalid username or password"}
            
            # Check if password needs to be changed
            must_change = user.get('must_change_password', False)
            if must_change:
                return {
                    "success": False, 
                    "message": "Password must be changed",
                    "user_id": user['id'],
                    "requires_password_change": True
                }
            
            # Generate OTP code and store it
            otp_code, expires_at = self.generate_otp()
            
            # Store the OTP code in the database
            self.db.update_user_otp(user['id'], otp_code, expires_at)
            
            # Send OTP email
            email_sent = self.send_otp_email(user['email'], otp_code, user['username'])
            
            if not email_sent:
                return {"success": False, "message": "Failed to send OTP email"}
            
            # Store user info for OTP verification
            self.current_user = {
                "id": user['id'],
                "username": user['username'],
                "email": user['email'],
                "role_id": user['role_id'],
                "requires_otp": True
            }
            
            return {
                "success": True,
                "message": "OTP sent to email",
                "user_id": user['id'],
                "email": user['email'],
                "requires_otp": True
            }
            
        except Exception as e:
            return {"success": False, "message": f"Login failed: {str(e)}"}

    def verify_otp(self, otp_code: str) -> Dict[str, Any]:
        """Verify OTP - Step 2: Complete login"""
        if not self.current_user or not self.current_user.get('requires_otp'):
            return {"success": False, "message": "OTP verification not required"}
        
        user_id = self.current_user['id']
        
        # Verify the actual OTP code, not a secret
        if not self.db.verify_user_otp(user_id, otp_code):
            return {"success": False, "message": "Invalid or expired OTP"}
        
        # Create session
        session_token = self.create_session(user_id)
        
        # Get user details
        user = self.db.get_user(self.current_user['username'])
        
        # Get role permissions
        role_permissions = self.db.get_role_permissions(user['role_id'])
        
        self.current_user = dict(user)
        self.current_session = session_token
        self.current_role = user.get('role_name', 'Analyst')
        self.permissions = role_permissions
        
        # Clear the OTP from database after successful verification
        self.db.clear_user_otp(user_id)
        
        # Log successful login
        self.db.log_audit_event(
            user_id=user_id,
            username=user['username'],
            action="login",
            status="success",
            details={"method": "otp"}
        )
        
        # Update last login
        self.db.update_user_last_login(user_id)
        
        return {
            "success": True,
            "message": "Login successful",
            "user_id": user_id,
            "username": user['username'],
            "role": self.current_role,
            "session_token": session_token
        }
    
    def create_session(self, user_id: int) -> str:
        """Create a new session token"""
        session_token = secrets.token_urlsafe(64)
        
        try:
            self.db.create_session(user_id, session_token, expires_hours=24)
            return session_token
        except Exception as e:
            print(f"❌ Failed to create session: {e}")
            raise
    
    def validate_session(self, session_token: str) -> bool:
        """Validate session token"""
        try:
            session = self.db.validate_session(session_token)
            if session:
                self.current_user = {
                    "id": session['user_id'],
                    "username": session['username'],
                    "role_id": session['role_id']
                }
                self.current_session = session_token
                self.current_role = session['role_name']
                self.permissions = session['permissions'] if session['permissions'] else {}
                return True
            return False
        except Exception as e:
            print(f"❌ Error validating session: {e}")
            return False
    
    def has_permission(self, permission: str) -> bool:
        """Check if current user has specific permission"""
        if not self.permissions:
            return False
        
        # Admin has all permissions
        if self.is_admin():
            return True
        
        # Check specific permission for Analyst
        return self.permissions.get(permission, False)
    
    def is_admin(self) -> bool:
        """Check if current user is Administrator"""
        return self.current_role == 'Administrator'
    
    def is_analyst(self) -> bool:
        """Check if current user is Analyst"""
        return self.current_role == 'Analyst'
    
    def logout(self, session_token: str = None):
        """Logout user"""
        token_to_invalidate = session_token or self.current_session
        if token_to_invalidate:
            self.db.invalidate_session(token_to_invalidate)
        
        self.current_user = None
        self.current_session = None
        self.current_role = None
        self.permissions = {}
    
    def change_password(self, user_id: int, old_password: str, new_password: str) -> Dict[str, Any]:
        """Change user password with session invalidation"""
        try:
            user = self.db.get_user_by_id(user_id)
            if not user:
                return {"success": False, "message": "User not found"}
            
            # Verify old password
            if not self.verify_password(old_password, user['password_hash']):
                return {"success": False, "message": "Current password is incorrect"}
            
            # Hash new password
            new_hash = self.hash_password(new_password)
            
            # Update password
            self.db.reset_user_password(user_id, new_hash, must_change=False)
            
            # Invalidate all sessions for this user
            from .utils import SessionInvalidator
            SessionInvalidator.invalidate_on_password_change(user_id, self.db, self)
            
            # Log password change
            self.db.log_audit_event(
                user_id=user_id,
                username=user['username'],
                action="password_change",
                status="success",
                details={"session_invalidation": "all_sessions_invalidated"}
            )
            
            return {"success": True, "message": "Password changed successfully. All existing sessions have been invalidated."}
            
        except Exception as e:
            return {"success": False, "message": f"Password change failed: {str(e)}"}
    
    def reset_password_request(self, email: str) -> Dict[str, Any]:
        """Request password reset"""
        try:
            user = self.db.get_user_by_email(email)
            if not user:
                return {"success": False, "message": "Email not found"}
            
            return {"success": True, "message": "Password reset email sent"}
            
        except Exception as e:
            return {"success": False, "message": f"Password reset failed: {str(e)}"}
    
    def get_current_user(self):
        """Get current logged in user"""
        return self.current_user
    
    def is_authenticated(self):
        """Check if user is authenticated"""
        return self.current_user is not None and self.current_session is not None