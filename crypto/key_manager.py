# crypto/key_manager.py
import os
import json
from datetime import datetime
from .multi_encrypt import MultiLevelEncryption
from .hmac_custom import CustomHMAC

class KeyManager:
    """
    Key Management System
    """
    
    def __init__(self, key_storage_file='keys.json'):
        self.key_storage_file = key_storage_file
        self.master_keys = {}
        self.user_keys = {}
        self.load_keys()
        
        if 'master' not in self.master_keys:
            self.generate_master_key()
    
    def generate_master_key(self):
        """Generate master key"""
        encryption = MultiLevelEncryption(128)
        self.master_keys['master'] = {
            'encryption': encryption,
            'public_keys': encryption.get_public_keys(),
            'created': datetime.now().isoformat()
        }
        self.save_keys()
    
    def generate_user_keys(self, user_id):
        """Generate keys for user"""
        if user_id in self.user_keys:
            return self.user_keys[user_id]
        
        encryption = MultiLevelEncryption(128)
        self.user_keys[user_id] = {
            'encryption': encryption,
            'public_keys': encryption.get_public_keys(),
            'created': datetime.now().isoformat(),
            'last_rotated': datetime.now().isoformat()
        }
        self.save_keys()
        
        return self.user_keys[user_id]
    
    def encrypt_user_data(self, user_id, data):
        """Encrypt data for user"""
        if user_id not in self.user_keys:
            self.generate_user_keys(user_id)
        
        encryption = self.user_keys[user_id]['encryption']
        return encryption.encrypt(data)
    
    def decrypt_user_data(self, user_id, encrypted_data):
        """Decrypt data for user"""
        if user_id not in self.user_keys:
            raise ValueError(f"No keys for user {user_id}")
        
        encryption = self.user_keys[user_id]['encryption']
        return encryption.decrypt(encrypted_data)
    
    def sign_data(self, data, user_id='master'):
        """Sign data with HMAC"""
        if user_id == 'master' and 'master' in self.master_keys:
            key_str = str(self.master_keys['master']['public_keys'])
        elif user_id in self.user_keys:
            key_str = str(self.user_keys[user_id]['public_keys'])
        else:
            key_str = user_id
        
        hmac = CustomHMAC(key_str.encode())
        return hmac.compute(json.dumps(data) if isinstance(data, dict) else str(data))
    
    def verify_signature(self, data, signature, user_id='master'):
        """Verify signature"""
        if user_id == 'master' and 'master' in self.master_keys:
            key_str = str(self.master_keys['master']['public_keys'])
        elif user_id in self.user_keys:
            key_str = str(self.user_keys[user_id]['public_keys'])
        else:
            key_str = user_id
        
        hmac = CustomHMAC(key_str.encode())
        return hmac.verify(json.dumps(data) if isinstance(data, dict) else str(data), signature)
    
    def save_keys(self):
        """Save keys to file"""
        save_data = {
            'master_keys': {},
            'user_keys': {}
        }
        
        if 'master' in self.master_keys:
            save_data['master_keys']['master'] = {
                'public_keys': self.master_keys['master']['public_keys'],
                'created': self.master_keys['master']['created']
            }
        
        for user_id, keys in self.user_keys.items():
            save_data['user_keys'][user_id] = {
                'public_keys': keys['public_keys'],
                'created': keys['created'],
                'last_rotated': keys.get('last_rotated')
            }
        
        with open(self.key_storage_file, 'w') as f:
            json.dump(save_data, f, indent=2)
    
    def load_keys(self):
        """Load keys from file"""
        if os.path.exists(self.key_storage_file):
            with open(self.key_storage_file, 'r') as f:
                data = json.load(f)
            
            if 'master_keys' in data:
                self.master_keys = data['master_keys']
            if 'user_keys' in data:
                self.user_keys = data['user_keys']