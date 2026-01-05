# utils/auth.py - SIMPLIFIED VERSION
"""
Authentication utilities without external dependencies
"""

import hashlib
import secrets
import base64
from datetime import datetime

class AuthUtils:
    """Authentication utilities"""
    
    @staticmethod
    def hash_password(password):
        """Simple password hash for demo"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def verify_password(password, stored_hash):
        """Verify password"""
        computed_hash = hashlib.sha256(password.encode()).hexdigest()
        return computed_hash == stored_hash
    
    @staticmethod
    def generate_session_token(user_id, username, role):
        """Generate simple session token"""
        data = f"{user_id}:{username}:{role}:{datetime.now().isoformat()}"
        return base64.b64encode(data.encode()).decode()
    
    @staticmethod
    def verify_session_token(token):
        """Verify session token"""
        try:
            data = base64.b64decode(token.encode()).decode()
            parts = data.split(':')
            if len(parts) >= 3:
                return {
                    'user_id': int(parts[0]),
                    'username': parts[1],
                    'role': parts[2]
                }
        except:
            return None
        return None