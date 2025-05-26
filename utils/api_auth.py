import jwt
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app
from typing import Dict, Optional, List
import sqlite3
import threading

# Thread-safe database operations
db_lock = threading.Lock()

class APIKeyManager:
    """Manages API keys for external access to PortGuardian."""
    
    def __init__(self, db_path: str = "api_keys.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize the SQLite database for API keys."""
        with db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create api_keys table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT UNIQUE NOT NULL,
                    key_hash TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    permissions TEXT NOT NULL,
                    created_by TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_used DATETIME,
                    is_active BOOLEAN DEFAULT 1,
                    expires_at DATETIME
                )
            ''')
            
            # Create api_usage table for tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    method TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    response_code INTEGER,
                    FOREIGN KEY (key_id) REFERENCES api_keys (key_id)
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_key_id ON api_keys(key_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_usage_key_id ON api_usage(key_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_usage_timestamp ON api_usage(timestamp)')
            
            conn.commit()
            conn.close()
    
    def generate_api_key(self, 
                        name: str, 
                        description: str = "",
                        permissions: List[str] = None,
                        created_by: str = "system",
                        expires_days: Optional[int] = None) -> Dict[str, str]:
        """Generate a new API key."""
        
        if permissions is None:
            permissions = ["read"]
        
        # Generate key components
        key_id = secrets.token_urlsafe(16)
        api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Calculate expiration
        expires_at = None
        if expires_days:
            expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat()
        
        try:
            with db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO api_keys 
                    (key_id, key_hash, name, description, permissions, created_by, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    key_id, key_hash, name, description, 
                    ','.join(permissions), created_by, expires_at
                ))
                
                conn.commit()
                conn.close()
            
            return {
                'key_id': key_id,
                'api_key': f"pg_{key_id}_{api_key}",
                'name': name,
                'permissions': permissions,
                'expires_at': expires_at
            }
        
        except Exception as e:
            raise Exception(f"Failed to generate API key: {str(e)}")
    
    def validate_api_key(self, api_key: str) -> Optional[Dict]:
        """Validate an API key and return key info if valid."""
        
        try:
            # Parse API key format: pg_{key_id}_{secret}
            if not api_key.startswith('pg_'):
                return None
            
            parts = api_key.split('_')
            if len(parts) != 3:
                return None
            
            key_id = parts[1]
            secret = parts[2]
            secret_hash = hashlib.sha256(secret.encode()).hexdigest()
            
            with db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT key_id, name, permissions, expires_at, is_active
                    FROM api_keys 
                    WHERE key_id = ? AND key_hash = ? AND is_active = 1
                ''', (key_id, secret_hash))
                
                result = cursor.fetchone()
                
                if result:
                    key_id, name, permissions, expires_at, is_active = result
                    
                    # Check expiration
                    if expires_at:
                        if datetime.now() > datetime.fromisoformat(expires_at):
                            conn.close()
                            return None
                    
                    # Update last used
                    cursor.execute('''
                        UPDATE api_keys SET last_used = CURRENT_TIMESTAMP 
                        WHERE key_id = ?
                    ''', (key_id,))
                    
                    conn.commit()
                    conn.close()
                    
                    return {
                        'key_id': key_id,
                        'name': name,
                        'permissions': permissions.split(',') if permissions else [],
                        'expires_at': expires_at
                    }
                
                conn.close()
                return None
        
        except Exception:
            return None
    
    def log_api_usage(self, key_id: str, endpoint: str, method: str, 
                     ip_address: str = None, user_agent: str = None, 
                     response_code: int = 200):
        """Log API usage for analytics."""
        
        try:
            with db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO api_usage 
                    (key_id, endpoint, method, ip_address, user_agent, response_code)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (key_id, endpoint, method, ip_address, user_agent, response_code))
                
                conn.commit()
                conn.close()
        
        except Exception:
            pass  # Don't fail the request if logging fails
    
    def get_api_keys(self) -> List[Dict]:
        """Get all API keys (without secrets)."""
        
        with db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT key_id, name, description, permissions, created_by, 
                       created_at, last_used, is_active, expires_at
                FROM api_keys 
                ORDER BY created_at DESC
            ''')
            
            columns = [description[0] for description in cursor.description]
            rows = cursor.fetchall()
            
            conn.close()
            
            return [dict(zip(columns, row)) for row in rows]
    
    def revoke_api_key(self, key_id: str) -> bool:
        """Revoke an API key."""
        
        try:
            with db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE api_keys SET is_active = 0 
                    WHERE key_id = ?
                ''', (key_id,))
                
                success = cursor.rowcount > 0
                conn.commit()
                conn.close()
                
                return success
        
        except Exception:
            return False

# Global API key manager
api_key_manager = APIKeyManager()

def require_api_key(permissions: List[str] = None):
    """Decorator to require API key authentication."""
    
    if permissions is None:
        permissions = ["read"]
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check for API key in header
            api_key = request.headers.get('X-API-Key')
            if not api_key:
                return jsonify({
                    'error': 'API key required',
                    'message': 'Please provide an API key in the X-API-Key header'
                }), 401
            
            # Validate API key
            key_info = api_key_manager.validate_api_key(api_key)
            if not key_info:
                return jsonify({
                    'error': 'Invalid API key',
                    'message': 'The provided API key is invalid or expired'
                }), 401
            
            # Check permissions
            key_permissions = key_info.get('permissions', [])
            if not any(perm in key_permissions for perm in permissions + ['admin']):
                return jsonify({
                    'error': 'Insufficient permissions',
                    'message': f'This API key does not have required permissions: {permissions}'
                }), 403
            
            # Log API usage
            api_key_manager.log_api_usage(
                key_id=key_info['key_id'],
                endpoint=request.endpoint,
                method=request.method,
                ip_address=request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
                user_agent=request.headers.get('User-Agent', ''),
                response_code=200
            )
            
            # Add key info to request context
            request.api_key_info = key_info
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def generate_jwt_token(payload: Dict, secret_key: str, expires_hours: int = 24) -> str:
    """Generate a JWT token."""
    
    payload['exp'] = datetime.utcnow() + timedelta(hours=expires_hours)
    payload['iat'] = datetime.utcnow()
    
    return jwt.encode(payload, secret_key, algorithm='HS256')

def verify_jwt_token(token: str, secret_key: str) -> Optional[Dict]:
    """Verify a JWT token."""
    
    try:
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
