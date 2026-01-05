# crypto/multi_encrypt.py
import json
import base64
from .rsa_custom import CustomRSA
from .ecc_custom import CustomECC

class MultiLevelEncryption:
    """
    Multi-level encryption combining RSA and ECC
    """
    
    def __init__(self, rsa_key_size=128):  # Small for demo
        self.rsa = CustomRSA(rsa_key_size)
        self.ecc = CustomECC('demo')
        
        self.rsa_keys = self.rsa.generate_keys()
        self.ecc_keys = self.ecc.generate_keys()
        
        self.rsa_public = self.rsa_keys['public_key']
        self.rsa_private = self.rsa_keys['private_key']
        self.ecc_public = self.ecc_keys['public_key']
        self.ecc_private = self.ecc_keys['private_key']
    
    def encrypt(self, data):
        """
        Encrypt with ECC, then RSA
        """
        if isinstance(data, dict):
            data_str = json.dumps(data)
        else:
            data_str = str(data)
        
        try:
            # ECC encryption
            ecc_encrypted = self.ecc.encrypt_message(data_str, self.ecc_public)
            
            ecc_data_str = json.dumps({
                'R': self.ecc.point_to_string(ecc_encrypted['R']),
                'ciphertext': str(ecc_encrypted['ciphertext'])
            })
            
            # RSA encryption
            rsa_encrypted = self.rsa.encrypt_string(ecc_data_str, self.rsa_public)
            
            return base64.b64encode(rsa_encrypted).decode('utf-8')
        except Exception as e:
            print(f"Encryption error: {e}")
            return base64.b64encode(data_str.encode()).decode('utf-8')
    
    def decrypt(self, encrypted_data):
        """
        Decrypt with RSA, then ECC
        """
        try:
            rsa_encrypted = base64.b64decode(encrypted_data)
            ecc_data_str = self.rsa.decrypt_string(rsa_encrypted, self.rsa_private)
            
            ecc_data = json.loads(ecc_data_str)
            x_str, y_str = ecc_data['R'].split(',')
            R = (int(x_str), int(y_str))
            
            ecc_encrypted = {
                'R': R,
                'ciphertext': int(ecc_data['ciphertext'])
            }
            
            decrypted = self.ecc.decrypt_message(ecc_encrypted, self.ecc_private)
            
            try:
                return json.loads(decrypted)
            except:
                return decrypted
        except Exception as e:
            print(f"Decryption error: {e}")
            try:
                return base64.b64decode(encrypted_data).decode('utf-8')
            except:
                return f"Decryption failed: {str(e)}"
    
    def get_public_keys(self):
        """Get public keys"""
        return {
            'rsa_public': self.rsa_public,
            'ecc_public': self.ecc.point_to_string(self.ecc_public)
        }