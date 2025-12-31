import os
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime
from typing import Optional, List, Dict, Any
import json
from dotenv import load_dotenv
import urllib.parse

load_dotenv()

class DatabaseManager:
    """Manage PostgreSQL database operations"""
    
    def __init__(self):
        self.conn = None
        self.connect()
        self.init_database()
    
    def connect(self):
        """Connect to Neon PostgreSQL database"""
        try:
            # Direct Neon PostgreSQL connection string
            connection_string = (
                "postgresql://neondb_owner:npg_xwSq6emIHk2v@"
                "ep-jolly-hall-abac7zg7-pooler.eu-west-2.aws.neon.tech/"
                "neondb?sslmode=require&channel_binding=require"
            )
            
            # Parse the connection string for debugging
            parsed_url = urllib.parse.urlparse(connection_string)
            
            print(f"🔌 Connecting to Neon PostgreSQL...")
            print(f"   Host: {parsed_url.hostname}")
            print(f"   Database: {parsed_url.path[1:]}")
            print(f"   User: {parsed_url.username}")
            
            # Connect using the connection string directly
            self.conn = psycopg2.connect(
                connection_string,
                connect_timeout=10,
                keepalives=1,
                keepalives_idle=30,
                keepalives_interval=10,
                keepalives_count=5
            )
            
            # Set connection parameters for Neon
            self.conn.autocommit = False
            
            # Test the connection
            with self.conn.cursor() as cursor:
                cursor.execute("SELECT version();")
                version = cursor.fetchone()[0]
                print(f"✅ Connected to Neon PostgreSQL")
                print(f"   PostgreSQL Version: {version}")
                
                # Check current database
                cursor.execute("SELECT current_database();")
                db_name = cursor.fetchone()[0]
                print(f"   Current Database: {db_name}")
                
                # List existing tables
                cursor.execute("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public'
                    ORDER BY table_name;
                """)
                tables = cursor.fetchall()
                print(f"   Existing tables: {[t[0] for t in tables] if tables else 'None'}")
                
        except psycopg2.OperationalError as e:
            print(f"❌ Database connection failed: {e}")
            print("\nTroubleshooting tips:")
            print("1. Check if your Neon database is running")
            print("2. Verify the connection string is correct")
            print("3. Check if your IP is allowed in Neon project settings")
            print("4. Ensure you have sufficient credits in your Neon account")
            raise
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            raise
    
    def init_database(self):
        """Initialize database tables (idempotent)"""
        try:
            with self.conn.cursor() as cursor:
                # Create users table if not exists
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        email VARCHAR(100),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP WITH TIME ZONE,
                        is_active BOOLEAN DEFAULT TRUE,
                        CONSTRAINT users_username_unique UNIQUE(username)
                    );
                
                    -- Create index for faster username lookups
                    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                """)
            
                # Create models table if not exists
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS models (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        name VARCHAR(100) NOT NULL,
                        description TEXT,
                        model_path VARCHAR(255) NOT NULL,
                        model_type VARCHAR(50) DEFAULT 'dca_dae',
                        accuracy DECIMAL(5,4),
                        precision DECIMAL(5,4),
                        recall DECIMAL(5,4),
                        f1_score DECIMAL(5,4),
                        training_samples INTEGER,
                        features_count INTEGER,
                        parameters JSONB,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        is_active BOOLEAN DEFAULT TRUE,
                        CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                    );
                
                    -- Create indexes for models
                    CREATE INDEX IF NOT EXISTS idx_models_user_id ON models(user_id);
                    CREATE INDEX IF NOT EXISTS idx_models_created_at ON models(created_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_models_name ON models(name);
                """)
            
                # Create detection_history table if not exists
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS detection_history (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        model_id INTEGER REFERENCES models(id) ON DELETE CASCADE,
                        input_file VARCHAR(255),
                        total_samples INTEGER DEFAULT 0,
                        anomalies_detected INTEGER DEFAULT 0,
                        detection_results JSONB,
                        processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        CONSTRAINT fk_detection_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                        CONSTRAINT fk_detection_model FOREIGN KEY(model_id) REFERENCES models(id) ON DELETE CASCADE
                    );
                
                    -- Create indexes for detection_history
                    CREATE INDEX IF NOT EXISTS idx_detection_history_user_id ON detection_history(user_id);
                    CREATE INDEX IF NOT EXISTS idx_detection_history_model_id ON detection_history(model_id);
                    CREATE INDEX IF NOT EXISTS idx_detection_history_processed_at ON detection_history(processed_at DESC);
                """)
            
                # FIXED: Create sessions table without problematic partial index
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS sessions (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        session_token VARCHAR(255) UNIQUE NOT NULL,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                        is_valid BOOLEAN DEFAULT TRUE,
                        CONSTRAINT sessions_token_unique UNIQUE(session_token),
                        CONSTRAINT fk_sessions_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                    );
                
                    -- Create indexes for sessions (FIXED: removed partial index with CURRENT_TIMESTAMP)
                    CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
                    CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
                    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
                
                    -- Create index for faster session validation (FIXED version)
                    CREATE INDEX IF NOT EXISTS idx_sessions_valid ON sessions(session_token) 
                    WHERE is_valid = TRUE;
                """)
            
                # Create model_versions table for versioning support
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS model_versions (
                        id SERIAL PRIMARY KEY,
                        model_id INTEGER REFERENCES models(id) ON DELETE CASCADE,
                        version INTEGER NOT NULL,
                        model_path VARCHAR(255) NOT NULL,
                        accuracy DECIMAL(5,4),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        notes TEXT,
                        CONSTRAINT unique_model_version UNIQUE(model_id, version),
                        CONSTRAINT fk_model_version FOREIGN KEY(model_id) REFERENCES models(id) ON DELETE CASCADE
                    );
                
                    CREATE INDEX IF NOT EXISTS idx_model_versions_model_id ON model_versions(model_id);
                """)
            
                self.conn.commit()
                print("✅ Database tables initialized/verified")
            
                # Verify tables were created
                cursor.execute("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name IN ('users', 'models', 'detection_history', 'sessions', 'model_versions')
                    ORDER BY table_name;
                """)
                existing_tables = [row[0] for row in cursor.fetchall()]
                print(f"   Available tables: {existing_tables}")
            
        except Exception as e:
            self.conn.rollback()
            print(f"❌ Database initialization failed: {e}")
            # Try to get more details about the error
            import traceback
            print(f"Full traceback:\n{traceback.format_exc()}")
            raise
    
    def create_user(self, username: str, password_hash: str, email: Optional[str] = None) -> int:
        """Create a new user"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO users (username, password_hash, email, last_login)
                    VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (username) DO NOTHING
                    RETURNING id
                """, (username, password_hash, email))
                
                result = cursor.fetchone()
                if result:
                    user_id = result[0]
                    self.conn.commit()
                    print(f"✅ User '{username}' created with ID: {user_id}")
                    return user_id
                else:
                    # User already exists
                    self.conn.rollback()
                    raise ValueError(f"User '{username}' already exists")
                    
        except Exception as e:
            self.conn.rollback()
            print(f"❌ Failed to create user '{username}': {e}")
            raise
    
    def get_user(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT id, username, password_hash, email, created_at, last_login, is_active
                    FROM users 
                    WHERE username = %s AND is_active = TRUE
                """, (username,))
                user = cursor.fetchone()
                return dict(user) if user else None
        except Exception as e:
            print(f"❌ Error getting user '{username}': {e}")
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
    
    def save_model(self, user_id: int, model_name: str, model_path: str, 
                   metrics: Dict[str, Any], parameters: Dict[str, Any]) -> int:
        """Save model metadata to database"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO models (
                        user_id, name, model_path, accuracy, precision,
                        recall, f1_score, training_samples, features_count,
                        parameters, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    RETURNING id
                """, (
                    user_id, model_name, model_path,
                    metrics.get('accuracy'), metrics.get('precision'),
                    metrics.get('recall'), metrics.get('f1_score'),
                    metrics.get('training_samples'), metrics.get('features_count'),
                    json.dumps(parameters)
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
    
    def delete_model(self, model_id: int, user_id: int) -> bool:
        """Soft delete a model"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE models 
                    SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s AND user_id = %s AND is_active = TRUE
                    RETURNING id
                """, (model_id, user_id))
                result = cursor.fetchone()
                self.conn.commit()
                if result:
                    print(f"✅ Model {model_id} deleted")
                    return True
                return False
        except Exception as e:
            self.conn.rollback()
            print(f"❌ Failed to delete model {model_id}: {e}")
            return False
    
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
        """Save detection results to history"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO detection_history (
                        user_id, model_id, input_file, total_samples,
                        anomalies_detected, detection_results
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    user_id, model_id, input_file,
                    results.get('total_samples', 0),
                    results.get('anomalies_detected', 0),
                    json.dumps(results)
                ))
                history_id = cursor.fetchone()[0]
                self.conn.commit()
                print(f"✅ Detection saved with ID: {history_id}")
                return history_id
        except Exception as e:
            self.conn.rollback()
            print(f"❌ Failed to save detection: {e}")
            raise
    
    def get_detection_history(self, user_id: int, limit: int = 10) -> List[Dict]:
        """Get detection history for a user"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT dh.*, m.name as model_name
                    FROM detection_history dh
                    JOIN models m ON dh.model_id = m.id
                    WHERE dh.user_id = %s
                    ORDER BY dh.processed_at DESC
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
                    SELECT s.*, u.username, u.id as user_id
                    FROM sessions s
                    JOIN users u ON s.user_id = u.id
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
                        (SELECT COUNT(*) FROM detection_history) as detection_count,
                        (SELECT COUNT(*) FROM sessions WHERE is_valid = TRUE AND expires_at > CURRENT_TIMESTAMP) as active_sessions
                """)
                counts = cursor.fetchone()
                stats['counts'] = dict(counts) if counts else {}
                
                # Get recent activity
                cursor.execute("""
                    SELECT 
                        (SELECT MAX(created_at) FROM users) as last_user_created,
                        (SELECT MAX(created_at) FROM models) as last_model_created,
                        (SELECT MAX(processed_at) FROM detection_history) as last_detection
                """)
                activity = cursor.fetchone()
                stats['activity'] = dict(activity) if activity else {}
                
                return stats
        except Exception as e:
            print(f"❌ Error getting database stats: {e}")
            return {}
    
    def close(self):
        """Close database connection"""
        if self.conn:
            try:
                # Check if connection is still alive
                with self.conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                print("✅ Database connection healthy")
            except Exception as e:
                print(f"⚠️ Database connection issue: {e}")
            
            self.conn.close()
            print("✅ Database connection closed")

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
    
    def backup_database(self):
        """Create a backup of important data"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                backup_data = {}
                
                # Backup users
                cursor.execute("SELECT * FROM users WHERE is_active = TRUE")
                backup_data['users'] = [dict(row) for row in cursor.fetchall()]
                
                # Backup models
                cursor.execute("SELECT * FROM models WHERE is_active = TRUE")
                backup_data['models'] = [dict(row) for row in cursor.fetchall()]
                
                # Save to file
                backup_file = f"database_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(backup_file, 'w') as f:
                    json.dump(backup_data, f, indent=2, default=str)
                
                print(f"✅ Database backup created: {backup_file}")
                return backup_file
        except Exception as e:
            print(f"❌ Database backup failed: {e}")
            return None