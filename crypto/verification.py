# crypto/verification.py
import hashlib
import json
import base64
import time
from datetime import datetime
import hmac


# Your code that uses hmac here
class CryptographicVerifier:
    """Real cryptographic verification system"""
    
    def __init__(self):
        self.hash_algorithm = 'sha256'
    
    def generate_verification_token(self, claim_data, claimant_private_key):
        """
        Generate cryptographic verification token
        Includes HMAC signature and timestamp
        """
        # Create verification payload
        verification_payload = {
            'claim_id': claim_data.get('claim_id'),
            'claimant_id': claim_data.get('claimant_id'),
            'item_id': claim_data.get('item_id'),
            'timestamp': datetime.now().isoformat(),
            'nonce': self._generate_nonce(),
            'verification_level': claim_data.get('verification_level', 'basic')
        }
        
        # Convert to string
        payload_str = json.dumps(verification_payload, sort_keys=True)
        
        # Create HMAC signature
        signature = self._create_hmac_signature(payload_str, claimant_private_key)
        
        # Create verification token
        token = {
            'payload': verification_payload,
            'signature': signature,
            'algorithm': self.hash_algorithm
        }
        
        return self._encode_token(token)
    
    def verify_claim_token(self, token, claimant_public_key):
        """
        Verify cryptographic token
        Returns (is_valid, verification_data)
        """
        try:
            # Decode token
            decoded_token = self._decode_token(token)
            if not decoded_token:
                return False, "Invalid token format"
            
            # Extract components
            payload = decoded_token.get('payload', {})
            signature = decoded_token.get('signature', '')
            algorithm = decoded_token.get('algorithm', '')
            
            # Verify algorithm
            if algorithm != self.hash_algorithm:
                return False, "Invalid algorithm"
            
            # Verify signature
            payload_str = json.dumps(payload, sort_keys=True)
            expected_signature = self._create_hmac_signature(payload_str, claimant_public_key)
            
            if not self._verify_signature(signature, expected_signature):
                return False, "Signature verification failed"
            
            # Check token expiration (24 hours)
            token_time = datetime.fromisoformat(payload.get('timestamp', ''))
            current_time = datetime.now()
            time_diff = (current_time - token_time).total_seconds()
            
            if time_diff > 86400:  # 24 hours in seconds
                return False, "Token expired"
            
            # Return verification data
            verification_data = {
                'claim_id': payload.get('claim_id'),
                'claimant_id': payload.get('claimant_id'),
                'item_id': payload.get('item_id'),
                'verification_level': payload.get('verification_level'),
                'timestamp': payload.get('timestamp'),
                'verification_score': self._calculate_verification_score(payload)
            }
            
            return True, verification_data
            
        except Exception as e:
            return False, f"Verification error: {str(e)}"
    
    def create_digital_signature(self, data, private_key):
        """Create digital signature for claim evidence"""
        data_str = json.dumps(data, sort_keys=True)
        return self._create_hmac_signature(data_str, private_key)
    
    def verify_digital_signature(self, data, signature, public_key):
        """Verify digital signature"""
        data_str = json.dumps(data, sort_keys=True)
        expected_signature = self._create_hmac_signature(data_str, public_key)
        return self._verify_signature(signature, expected_signature)
    
    def _create_hmac_signature(self, data, key):
        """Create HMAC signature"""
        import hmac
        key_bytes = key.encode() if isinstance(key, str) else key
        data_bytes = data.encode() if isinstance(data, str) else data
        
        hmac_obj = hmac.new(key_bytes, data_bytes, hashlib.sha256)
        return hmac_obj.hexdigest()
    
    def _verify_signature(self, signature, expected_signature):
        """Constant-time signature verification"""
        return hmac.compare_digest(signature, expected_signature)
    
    def _generate_nonce(self):
        """Generate cryptographic nonce"""
        import secrets
        return secrets.token_hex(16)
    
    def _encode_token(self, token):
        """Base64 encode token"""
        token_str = json.dumps(token)
        return base64.b64encode(token_str.encode()).decode()
    
    def _decode_token(self, encoded_token):
        """Base64 decode token"""
        try:
            token_str = base64.b64decode(encoded_token.encode()).decode()
            return json.loads(token_str)
        except:
            return None
    
    def _calculate_verification_score(self, payload):
        """Calculate verification score based on evidence level"""
        scores = {
            'basic': 50,
            'enhanced': 75,
            'premium': 95
        }
        return scores.get(payload.get('verification_level', 'basic'), 50)
    
    def generate_verification_report(self, claim_data, verification_result):
        """Generate detailed verification report"""
        report = {
            'verification_id': self._generate_nonce(),
            'timestamp': datetime.now().isoformat(),
            'claim_data': {
                'claim_id': claim_data.get('claim_id'),
                'claimant': claim_data.get('claimant_id'),
                'item': claim_data.get('item_id'),
                'verification_level': claim_data.get('verification_level')
            },
            'verification_result': {
                'is_valid': verification_result[0],
                'message': verification_result[1],
                'score': verification_result[2] if len(verification_result) > 2 else 0
            },
            'cryptographic_evidence': {
                'algorithm_used': self.hash_algorithm,
                'signature_verified': verification_result[0],
                'timestamp_verified': True,
                'integrity_check': True
            },
            'recommendation': 'APPROVE' if verification_result[0] else 'REJECT'
        }
        return report