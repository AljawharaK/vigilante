import bcrypt
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from .database import DatabaseManager

class AuthManager:
    """Handle user authentication and authorization"""
    
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.current_user = None
        self.current_session = None
    
    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify a password against its hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def register(self, username: str, password: str, email: Optional[str] = None) -> Dict[str, Any]:
        """Register a new user"""
        try:
            # Check if user exists
            existing_user = self.db.get_user(username)
            if existing_user:
                return {"success": False, "message": "Username already exists"}
            
            # Hash password
            password_hash = self.hash_password(password)
            
            # Create user
            user_id = self.db.create_user(username, password_hash, email)
            
            # Create session
            session_token = self.create_session(user_id)
            
            self.current_user = {"id": user_id, "username": username}
            self.current_session = session_token
            
            return {
                "success": True,
                "message": "User registered successfully",
                "user_id": user_id,
                "session_token": session_token
            }
            
        except Exception as e:
            return {"success": False, "message": f"Registration failed: {str(e)}"}
    
    def login(self, username: str, password: str) -> Dict[str, Any]:
        """Login user"""
        try:
            # Get user from database
            user = self.db.get_user(username)
            if not user:
                return {"success": False, "message": "Invalid username or password"}
            
            # Verify password
            if not self.verify_password(password, user['password_hash']):
                return {"success": False, "message": "Invalid username or password"}
            
            # Create session
            session_token = self.create_session(user['id'])
            
            self.current_user = dict(user)
            self.current_session = session_token
            
            return {
                "success": True,
                "message": "Login successful",
                "user_id": user['id'],
                "username": user['username'],
                "session_token": session_token
            }
            
        except Exception as e:
            return {"success": False, "message": f"Login failed: {str(e)}"}
    
    def create_session(self, user_id: int) -> str:
        """Create a new session token"""
        session_token = secrets.token_urlsafe(32)
        self.db.create_session(user_id, session_token)
        return session_token
    
    def validate_session(self, session_token: str) -> bool:
        """Validate session token"""
        session = self.db.validate_session(session_token)
        if session:
            self.current_user = {"id": session['user_id'], "username": session['username']}
            self.current_session = session_token
            return True
        return False
    
    def logout(self, session_token: str):
        """Logout user by invalidating session"""
        self.db.invalidate_session(session_token)
        self.current_user = None
        self.current_session = None
    
    def get_current_user(self):
        """Get current logged in user"""
        return self.current_user
    
    def is_authenticated(self):
        """Check if user is authenticated"""
        return self.current_user is not None and self.current_session is not None