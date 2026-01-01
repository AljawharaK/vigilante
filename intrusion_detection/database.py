# intrusion_detection/database.py
import os
import psycopg2
from psycopg2.extras import RealDictCursor, DictCursor
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import json
import numpy as np
import pandas as pd
from dotenv import load_dotenv
import urllib.parse

load_dotenv()

class DatabaseManager:
    """Manage PostgreSQL database operations with enhanced schema"""
    
    def __init__(self):
        self.conn = None
        self.connect()
        self.init_database()
    
    def connect(self):
        """Connect to Neon PostgreSQL database"""
        try:
            connection_string = os.getenv(
                "DATABASE_URL",
                "postgresql://neondb_owner:npg_xwSq6emIHk2v@"
                "ep-jolly-hall-abac7zg7-pooler.eu-west-2.aws.neon.tech/"
                "neondb?sslmode=require&channel_binding=require"
            )
            
            self.conn = psycopg2.connect(
                connection_string,
                connect_timeout=10,
                keepalives=1,
                keepalives_idle=30,
                keepalives_interval=10,
                keepalives_count=5
            )
            
            self.conn.autocommit = False
            print("✅ Connected to database")
            
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            raise
    
    def init_database(self):
        """Initialize database tables with enhanced schema"""
        try:
            with self.conn.cursor() as cursor:
                # Create roles table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS roles (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(50) UNIQUE NOT NULL,
                        description TEXT,
                        permissions JSONB DEFAULT '{}',
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                
                # Create users table with role support
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        role_id INTEGER REFERENCES roles(id) DEFAULT 2, -- Default to Analyst
                        is_active BOOLEAN DEFAULT TRUE,
                        must_change_password BOOLEAN DEFAULT TRUE,
                        failed_login_attempts INTEGER DEFAULT 0,
                        last_login TIMESTAMP WITH TIME ZONE,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        otp_secret VARCHAR(100),
                        otp_expires_at TIMESTAMP WITH TIME ZONE,
                        CONSTRAINT users_username_unique UNIQUE(username),
                        CONSTRAINT users_email_unique UNIQUE(email)
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                    CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);
                """)
                
                # Create models table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS models (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        name VARCHAR(100) NOT NULL,
                        model_path VARCHAR(500) NOT NULL,
                        model_type VARCHAR(50) DEFAULT 'dca_dae',
                        dataset_name VARCHAR(100),
                        accuracy DECIMAL(5,4),
                        precision DECIMAL(5,4),
                        recall DECIMAL(5,4),
                        f1_score DECIMAL(5,4),
                        training_samples INTEGER,
                        features JSONB,
                        features_count INTEGER,
                        parameters JSONB,
                        metrics JSONB,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        is_active BOOLEAN DEFAULT TRUE,
                        version INTEGER DEFAULT 1,
                        CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_models_user_id ON models(user_id);
                    CREATE INDEX IF NOT EXISTS idx_models_created_at ON models(created_at DESC);
                """)
                
                # Create audit_logs table for immutable logging
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id BIGSERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        username VARCHAR(50),
                        action VARCHAR(100) NOT NULL,
                        resource VARCHAR(500),
                        status VARCHAR(50),
                        details JSONB,
                        ip_address VARCHAR(45),
                        user_agent TEXT,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        CONSTRAINT audit_logs_immutable CHECK (created_at <= CURRENT_TIMESTAMP)
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
                    CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
                    CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status);
                """)
                
                # Create detection_results table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS detection_results (
                        id BIGSERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        model_id INTEGER REFERENCES models(id),
                        input_file VARCHAR(500),
                        total_flows INTEGER,
                        anomalies_detected INTEGER,
                        false_positives INTEGER,
                        false_negatives INTEGER,
                        execution_time_seconds DECIMAL(10,2),
                        metrics JSONB,
                        results JSONB,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_detection_results_user_id ON detection_results(user_id);
                    CREATE INDEX IF NOT EXISTS idx_detection_results_created_at ON detection_results(created_at DESC);
                """)
                
                # Create sessions table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS sessions (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        session_token VARCHAR(255) UNIQUE NOT NULL,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                        last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        is_valid BOOLEAN DEFAULT TRUE,
                        CONSTRAINT sessions_token_unique UNIQUE(session_token),
                        CONSTRAINT fk_sessions_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
                    CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
                    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
                """)
                
                # Insert default roles
                cursor.execute("""
                    INSERT INTO roles (id, name, description, permissions) VALUES
                    (1, 'Administrator', 'Cybersecurity Administrator with full system access',
                     '{"manage_users": true, "manage_models": true, "view_audit_logs": true, 
                       "generate_reports": true, "system_config": true, "train_models": true, 
                       "run_detection": true, "view_summary": true, "generate_explanations": true}'),
                    (2, 'Analyst', 'Security Analyst with detection and analysis capabilities',
                     '{"train_models": true, "run_detection": true, "view_summary": true, 
                       "generate_explanations": true}')
                    ON CONFLICT (id) DO UPDATE SET 
                        name = EXCLUDED.name,
                        description = EXCLUDED.description,
                        permissions = EXCLUDED.permissions;
                """)
                
                # Create admin user if not exists - FIXED: Set must_change_password = TRUE
                cursor.execute("""
                    INSERT INTO users (username, password_hash, email, role_id, must_change_password)
                    SELECT 'admin1', '$2a$12$9tjqutyvxOG5HXBcWRJpmeoY.xdl38L1eqZri3Ahu0ppfcic1B7JW', 'example@gmail.com', 1, FALSE
                    WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin1');
                """)
                
                self.conn.commit()
                print("✅ Database tables initialized successfully")
                
        except Exception as e:
            self.conn.rollback()
            print(f"❌ Database initialization failed: {e}")
            raise
    
    def create_user(self, username: str, password_hash: str, email: str, 
                   role: str = 'Analyst', created_by: int = None) -> int:
        """Create a new user with simplified roles"""
        try:
            # Map role name to role_id
            role_map = {
                'Administrator': 1,
                'Analyst': 2
            }
            
            if role not in role_map:
                raise ValueError(f"Invalid role. Must be 'Administrator' or 'Analyst'")
            
            role_id = role_map[role]
            
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO users (username, password_hash, email, role_id, created_at)
                    VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                    RETURNING id
                """, (username, password_hash, email, role_id))
                
                user_id = cursor.fetchone()[0]
                self.conn.commit()
                return user_id
        except Exception as e:
            self.conn.rollback()
            raise
    
    def get_user(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT u.id, u.username, u.password_hash, u.email, 
                           u.role_id, u.is_active, u.must_change_password,
                           u.failed_login_attempts, u.last_login, u.created_at,
                           r.name as role_name, r.permissions
                    FROM users u
                    LEFT JOIN roles r ON u.role_id = r.id
                    WHERE u.username = %s AND u.is_active = TRUE
                """, (username,))
                user = cursor.fetchone()
                return dict(user) if user else None
        except Exception as e:
            print(f"❌ Error getting user '{username}': {e}")
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT u.*, r.name as role_name, r.permissions
                    FROM users u
                    LEFT JOIN roles r ON u.role_id = r.id
                    WHERE u.id = %s
                """, (user_id,))
                return cursor.fetchone()
        except Exception as e:
            print(f"Error getting user by ID: {e}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Get user by email"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT u.*, r.name as role_name, r.permissions
                    FROM users u
                    LEFT JOIN roles r ON u.role_id = r.id
                    WHERE u.email = %s
                """, (email,))
                return cursor.fetchone()
        except Exception as e:
            print(f"Error getting user by email: {e}")
            return None
    
    def update_user_last_login(self, user_id: int):
        """Update user's last login timestamp"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users 
                    SET last_login = CURRENT_TIMESTAMP
                    WHERE id = %s
                """, (user_id,))
                self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            print(f"⚠️ Failed to update last login for user {user_id}: {e}")
    
    def update_user_otp(self, user_id: int, otp_secret: str, expires_at: datetime):
        """Update user OTP secret and expiration"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users 
                    SET otp_secret = %s, otp_expires_at = %s
                    WHERE id = %s
                """, (otp_secret, expires_at, user_id))
                self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise
    
    def verify_user_otp(self, user_id: int, otp_secret: str) -> bool:
        """Verify user OTP"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    SELECT 1 FROM users 
                    WHERE id = %s AND otp_secret = %s 
                    AND otp_expires_at > CURRENT_TIMESTAMP
                """, (user_id, otp_secret))
                return cursor.fetchone() is not None
        except Exception as e:
            print(f"Error verifying OTP: {e}")
            return False
    
    def update_user_failed_attempts(self, user_id: int):
        """Update user's failed login attempts"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users 
                    SET failed_login_attempts = failed_login_attempts + 1
                    WHERE id = %s
                """, (user_id,))
                self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            print(f"Error updating failed attempts: {e}")
    
    def save_model(self, user_id: int, model_name: str, model_path: str, 
                   dataset_name: str = None, metrics: Dict[str, Any] = None,
                   features: List[str] = None, parameters: Dict[str, Any] = None) -> int:
        """Save model metadata to database"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO models (
                        user_id, name, model_path, dataset_name,
                        accuracy, precision, recall, f1_score,
                        training_samples, features_count,
                        features, parameters, metrics, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    RETURNING id
                """, (
                    user_id, model_name, model_path, dataset_name,
                    metrics.get('accuracy') if metrics else None,
                    metrics.get('precision') if metrics else None,
                    metrics.get('recall') if metrics else None,
                    metrics.get('f1_score') if metrics else None,
                    metrics.get('training_samples') if metrics else None,
                    metrics.get('features_count') if metrics else None,
                    json.dumps(features) if features else None,
                    json.dumps(parameters) if parameters else None,
                    json.dumps(metrics) if metrics else None
                ))
                model_id = cursor.fetchone()[0]
                self.conn.commit()
                print(f"✅ Model '{model_name}' saved with ID: {model_id}")
                return model_id
        except Exception as e:
            self.conn.rollback()
            print(f"❌ Failed to save model '{model_name}': {e}")
            raise
    
    def get_user_models(self, user_id: int) -> List[Dict]:
        """Get all models for a user"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT id, name, description, model_path, model_type,
                           accuracy, precision, recall, f1_score,
                           training_samples, features_count,
                           created_at, updated_at
                    FROM models 
                    WHERE user_id = %s AND is_active = TRUE
                    ORDER BY created_at DESC
                """, (user_id,))
                models = cursor.fetchall()
                return [dict(model) for model in models]
        except Exception as e:
            print(f"❌ Error getting models for user {user_id}: {e}")
            return []
    
    def get_model(self, model_id: int, user_id: Optional[int] = None) -> Optional[Dict]:
        """Get model by ID"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                if user_id:
                    cursor.execute("""
                        SELECT m.*, u.username as owner
                        FROM models m
                        JOIN users u ON m.user_id = u.id
                        WHERE m.id = %s AND m.user_id = %s AND m.is_active = TRUE
                    """, (model_id, user_id))
                else:
                    cursor.execute("""
                        SELECT m.*, u.username as owner
                        FROM models m
                        JOIN users u ON m.user_id = u.id
                        WHERE m.id = %s AND m.is_active = TRUE
                    """, (model_id,))
                model = cursor.fetchone()
                return dict(model) if model else None
        except Exception as e:
            print(f"❌ Error getting model {model_id}: {e}")
            return None
    
    def get_model_by_path(self, model_path: str, user_id: int) -> Optional[Dict]:
        """Get model by path and user ID"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT * FROM models 
                    WHERE model_path = %s AND user_id = %s AND is_active = TRUE
                """, (model_path, user_id))
                model = cursor.fetchone()
                return dict(model) if model else None
        except Exception as e:
            print(f"❌ Error getting model by path: {e}")
            return None
    
    def save_detection(self, user_id: int, model_id: int, input_file: str,
                      results: Dict[str, Any]) -> int:
        """Save detection results to history with proper JSON serialization"""
        try:
            # Convert results to JSON serializable format
            serializable_results = self._make_json_serializable(results)
        
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO detection_results (
                        user_id, model_id, input_file, total_flows,
                        anomalies_detected, metrics, results
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    user_id, 
                    model_id, 
                    input_file,
                    serializable_results.get('total_flows', 0),
                    serializable_results.get('anomalies_detected', 0),
                    json.dumps(serializable_results.get('metrics', {})),
                    json.dumps(serializable_results)
                ))
                history_id = cursor.fetchone()[0]
                self.conn.commit()
                print(f"✅ Detection saved with ID: {history_id}")
                return history_id
        except Exception as e:
            self.conn.rollback()
            print(f"❌ Failed to save detection: {e}")
            raise

    def _make_json_serializable(self, obj):
        """Convert numpy types to JSON serializable types"""
        if isinstance(obj, dict):
            return {k: self._make_json_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_json_serializable(v) for v in obj]
        elif isinstance(obj, tuple):
            return tuple(self._make_json_serializable(v) for v in obj)
        elif isinstance(obj, (np.integer, np.int64, np.int32)):
            return int(obj)
        elif isinstance(obj, (np.floating, np.float64, np.float32)):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif pd.isna(obj):
            return None
        else:
            return obj
    
    def get_detection_history(self, user_id: int, limit: int = 10) -> List[Dict]:
        """Get detection history for a user"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT dh.*, m.name as model_name
                    FROM detection_results dh
                    JOIN models m ON dh.model_id = m.id
                    WHERE dh.user_id = %s
                    ORDER BY dh.created_at DESC
                    LIMIT %s
                """, (user_id, limit))
                history = cursor.fetchall()
                return [dict(record) for record in history]
        except Exception as e:
            print(f"❌ Error getting detection history: {e}")
            return []
    
    def create_session(self, user_id: int, session_token: str, expires_hours: int = 24) -> int:
        """Create a new session"""
        try:
            from datetime import datetime, timedelta, timezone
            expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_hours)
            
            with self.conn.cursor() as cursor:
                # Clean up expired sessions first
                cursor.execute("""
                    DELETE FROM sessions 
                    WHERE expires_at < CURRENT_TIMESTAMP OR is_valid = FALSE
                """)
                
                # Create new session
                cursor.execute("""
                    INSERT INTO sessions (user_id, session_token, expires_at)
                    VALUES (%s, %s, %s)
                    RETURNING id
                """, (user_id, session_token, expires_at))
                session_id = cursor.fetchone()[0]
                self.conn.commit()
                return session_id
        except Exception as e:
            self.conn.rollback()
            print(f"❌ Failed to create session: {e}")
            raise
    
    def validate_session(self, session_token: str) -> Optional[Dict]:
        """Validate session token"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT s.*, u.username, u.id as user_id, u.role_id,
                           r.name as role_name, r.permissions
                    FROM sessions s
                    JOIN users u ON s.user_id = u.id
                    LEFT JOIN roles r ON u.role_id = r.id
                    WHERE s.session_token = %s 
                    AND s.is_valid = TRUE 
                    AND s.expires_at > CURRENT_TIMESTAMP
                    AND u.is_active = TRUE
                """, (session_token,))
                session = cursor.fetchone()
                return dict(session) if session else None
        except Exception as e:
            print(f"❌ Error validating session: {e}")
            return None
    
    def invalidate_session(self, session_token: str) -> bool:
        """Invalidate a session"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE sessions 
                    SET is_valid = FALSE 
                    WHERE session_token = %s
                    RETURNING id
                """, (session_token,))
                result = cursor.fetchone()
                self.conn.commit()
                return result is not None
        except Exception as e:
            self.conn.rollback()
            print(f"❌ Failed to invalidate session: {e}")
            return False
    
    def invalidate_user_sessions(self, user_id: int) -> int:
        """Invalidate all sessions for a user"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE sessions 
                    SET is_valid = FALSE 
                    WHERE user_id = %s AND is_valid = TRUE
                    RETURNING COUNT(*)
                """, (user_id,))
                count = cursor.fetchone()[0]
                self.conn.commit()
                print(f"✅ Invalidated {count} sessions for user {user_id}")
                return count
        except Exception as e:
            self.conn.rollback()
            print(f"❌ Failed to invalidate user sessions: {e}")
            return 0
    
    def log_audit_event(self, user_id: int, username: str, action: str, 
                       resource: str = None, status: str = "success", 
                       details: Dict = None, ip_address: str = None):
        """Log audit event"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO audit_logs 
                    (user_id, username, action, resource, status, details, ip_address, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                """, (user_id, username, action, resource, status, 
                     json.dumps(details) if details else None, ip_address))
                self.conn.commit()
        except Exception as e:
            print(f"Error logging audit event: {e}")
    
    def get_audit_logs(self, period_days: int = 30, user_id: int = None) -> List[Dict]:
        """Get audit logs for period"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                query = """
                    SELECT * FROM audit_logs 
                    WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL %s days
                """
                params = [period_days]
                
                if user_id:
                    query += " AND user_id = %s"
                    params.append(user_id)
                
                query += " ORDER BY created_at DESC"
                cursor.execute(query, tuple(params))
                return cursor.fetchall()
        except Exception as e:
            print(f"Error getting audit logs: {e}")
            return []
    
    def get_detection_summary(self, user_id: int = None, period_days: int = 7):
        """Get detection summary for period"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                query = """
                    SELECT 
                        DATE(created_at) as date,
                        COUNT(*) as total_detections,
                        SUM(total_flows) as total_flows,
                        SUM(anomalies_detected) as total_anomalies
                    FROM detection_results
                    WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL %s days
                """
                params = [period_days]
                
                if user_id:
                    query += " AND user_id = %s"
                    params.append(user_id)
                
                query += " GROUP BY DATE(created_at) ORDER BY date DESC"
                cursor.execute(query, tuple(params))
                return cursor.fetchall()
        except Exception as e:
            print(f"Error getting detection summary: {e}")
            return []
    
    def get_role_permissions(self, role_id: int) -> Dict:
        """Get permissions for a role"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT permissions FROM roles WHERE id = %s
                """, (role_id,))
                result = cursor.fetchone()
                return result['permissions'] if result else {}
        except Exception as e:
            print(f"Error getting role permissions: {e}")
            return {}
    
    def update_user_role(self, user_id: int, role: str, updated_by: int):
        """Update user role (simplified)"""
        try:
            # Map role name to role_id
            role_map = {
                'Administrator': 1,
                'Analyst': 2
            }
            
            if role not in role_map:
                raise ValueError(f"Invalid role. Must be 'Administrator' or 'Analyst'")
            
            role_id = role_map[role]
            
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users 
                    SET role_id = %s, updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                    RETURNING username
                """, (role_id, user_id))
                username = cursor.fetchone()[0]
                self.conn.commit()
                return username
        except Exception as e:
            self.conn.rollback()
            raise
    
    def deactivate_user(self, user_id: int, updated_by: int):
        """Deactivate user"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users 
                    SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                    RETURNING username
                """, (user_id,))
                username = cursor.fetchone()[0]
                self.conn.commit()
                return username
        except Exception as e:
            self.conn.rollback()
            raise
    
    def reset_user_password(self, user_id: int, password_hash: str, must_change: bool = True):
        """Reset user password"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users 
                    SET password_hash = %s, 
                        must_change_password = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                    RETURNING username
                """, (password_hash, must_change, user_id))
                username = cursor.fetchone()[0]
                self.conn.commit()
                return username
        except Exception as e:
            self.conn.rollback()
            raise
    
    def count_admins(self) -> int:
        """Count active Administrators"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    SELECT COUNT(*) as admin_count
                    FROM users u
                    JOIN roles r ON u.role_id = r.id
                    WHERE r.name = 'Administrator' 
                    AND u.is_active = TRUE
                """)
                result = cursor.fetchone()
                return result[0] if result else 0
        except Exception as e:
            print(f"Error counting admins: {e}")
            return 0
    
    def get_user_activity(self, period_days: int) -> Dict:
        """Get user activity statistics"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT 
                        COUNT(DISTINCT CASE WHEN action = 'login' THEN id END) as total_logins,
                        COUNT(DISTINCT CASE WHEN action = 'model_train' THEN id END) as models_trained,
                        COUNT(DISTINCT CASE WHEN action = 'detect' THEN id END) as detection_jobs_run
                    FROM audit_logs
                    WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL %s days
                """, (period_days,))
                result = cursor.fetchone()
                return dict(result) if result else {}
        except Exception as e:
            print(f"Error getting user activity: {e}")
            return {}
    
    def get_recent_anomalies(self, period_days: int, limit: int = 20):
        """Get recent anomalies"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT 
                        dr.created_at as detected_at,
                        dr.results::text as results_json
                    FROM detection_results dr
                    WHERE dr.created_at >= CURRENT_TIMESTAMP - INTERVAL %s days
                    AND dr.anomalies_detected > 0
                    ORDER BY dr.created_at DESC
                    LIMIT %s
                """, (period_days, limit))
                
                results = []
                for row in cursor.fetchall():
                    try:
                        results_data = json.loads(row['results_json'])
                        anomalies = results_data.get('anomalies', [])
                        for anomaly in anomalies[:5]:  # Get up to 5 per detection
                            anomaly['detected_at'] = row['detected_at']
                            results.append(anomaly)
                    except:
                        continue
                
                return results[:limit]  # Ensure we don't exceed limit
        except Exception as e:
            print(f"Error getting recent anomalies: {e}")
            return []
    
    def get_user_anomalies(self, user_id: int, period_days: int):
        """Get user's anomalies"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT 
                        dr.created_at as detected_at,
                        dr.results::text as results_json
                    FROM detection_results dr
                    WHERE dr.user_id = %s
                    AND dr.created_at >= CURRENT_TIMESTAMP - INTERVAL %s days
                    AND dr.anomalies_detected > 0
                    ORDER BY dr.created_at DESC
                    LIMIT 10
                """, (user_id, period_days))
                
                results = []
                for row in cursor.fetchall():
                    try:
                        results_data = json.loads(row['results_json'])
                        anomalies = results_data.get('anomalies', [])
                        for anomaly in anomalies[:5]:  # Get up to 5 per detection
                            anomaly['detected_at'] = row['detected_at']
                            results.append(anomaly)
                    except:
                        continue
                
                return results[:10]
        except Exception as e:
            print(f"Error getting user anomalies: {e}")
            return []
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                stats = {}
                
                # Get table counts
                cursor.execute("""
                    SELECT 
                        (SELECT COUNT(*) FROM users WHERE is_active = TRUE) as user_count,
                        (SELECT COUNT(*) FROM models WHERE is_active = TRUE) as model_count,
                        (SELECT COUNT(*) FROM detection_results) as detection_count,
                        (SELECT COUNT(*) FROM sessions WHERE is_valid = TRUE AND expires_at > CURRENT_TIMESTAMP) as active_sessions
                """)
                counts = cursor.fetchone()
                stats['counts'] = dict(counts) if counts else {}
                
                return stats
        except Exception as e:
            print(f"❌ Error getting database stats: {e}")
            return {}
    
    def health_check(self) -> bool:
        """Perform a health check on the database"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
                print("✅ Database health check: PASSED")
                return True
        except Exception as e:
            print(f"❌ Database health check: FAILED - {e}")
            return False
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            print("✅ Database connection closed")