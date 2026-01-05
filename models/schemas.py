# models/schemas.py
"""
Database schemas and data models for Lost & Found Portal
"""

from datetime import datetime
import json

class UserSchema:
    """User data schema"""
    
    @staticmethod
    def create_user_data(username, email, password_hash, full_name="", role="user"):
        """Create user data dictionary"""
        return {
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'full_name': full_name,
            'role': role,
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'two_factor_enabled': False,
            'two_factor_secret': None,
            'reputation_score': 0,
            'is_active': True
        }
    
    @staticmethod
    def validate_user_data(data):
        """Validate user data"""
        required_fields = ['username', 'email', 'password_hash']
        for field in required_fields:
            if field not in data:
                return False, f"Missing required field: {field}"
        
        if not isinstance(data['username'], str) or len(data['username']) < 3:
            return False, "Username must be at least 3 characters"
        
        if '@' not in data['email']:
            return False, "Invalid email format"
        
        return True, "Valid"

class ItemSchema:
    """Lost/Found item schema"""
    
    @staticmethod
    def create_item_data(user_id, title, description, location, item_type, category):
        """Create item data dictionary"""
        return {
            'title': title,
            'description': description,
            'location': location,
            'item_type': item_type,  # 'lost' or 'found'
            'category': category,
            'user_id': user_id,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'status': 'available',  # available, claimed, resolved
            'last_claimed_at': None,
            'claim_count': 0
        }
    
    @staticmethod
    def validate_item_data(data):
        """Validate item data"""
        required_fields = ['title', 'description', 'location', 'item_type', 'category', 'user_id']
        for field in required_fields:
            if field not in data:
                return False, f"Missing required field: {field}"
        
        if data['item_type'] not in ['lost', 'found']:
            return False, "Item type must be 'lost' or 'found'"
        
        if len(data['title']) < 3:
            return False, "Title must be at least 3 characters"
        
        if len(data['description']) < 10:
            return False, "Description must be at least 10 characters"
        
        return True, "Valid"

class ClaimSchema:
    """Claim schema"""
    
    @staticmethod
    def create_claim_data(item_id, claimant_id, claim_message, verification_level='basic'):
        """Create claim data dictionary"""
        return {
            'item_id': item_id,
            'claimant_id': claimant_id,
            'claim_message': claim_message,
            'verification_level': verification_level,
            'created_at': datetime.now().isoformat(),
            'status': 'pending',  # pending, approved, rejected, verified
            'owner_reviewed_at': None,
            'admin_reviewed_at': None,
            'reviewed_by': None,
            'admin_notes': None,
            'verification_score': 0
        }
    
    @staticmethod
    def validate_claim_data(data):
        """Validate claim data"""
        required_fields = ['item_id', 'claimant_id', 'claim_message']
        for field in required_fields:
            if field not in data:
                return False, f"Missing required field: {field}"
        
        if len(data['claim_message']) < 10:
            return False, "Claim message must be at least 10 characters"
        
        if 'verification_level' in data and data['verification_level'] not in ['basic', 'enhanced', 'premium']:
            return False, "Invalid verification level"
        
        return True, "Valid"

class AdminLogSchema:
    """Admin activity log schema"""
    
    @staticmethod
    def create_log_data(admin_id, action, target_type, target_id, details):
        """Create admin log data dictionary"""
        return {
            'admin_id': admin_id,
            'action': action,
            'target_type': target_type,  # 'user', 'item', 'claim'
            'target_id': target_id,
            'details': details,
            'timestamp': datetime.now().isoformat(),
            'ip_address': None,
            'user_agent': None
        }