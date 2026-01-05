# crypto/ecc_custom.py
import random
import hashlib

class CustomECC:
    """
    Custom Elliptic Curve Cryptography implementation
    Simplified for demonstration
    """
    
    def __init__(self, curve='demo'):
        if curve == 'demo':
            # Small curve for demo
            self.p = 101
            self.a = 0
            self.b = 7
            self.G = (2, 22)  # Valid point on curve
            self.n = 97
        else:
            # secp256k1 would go here
            pass
    
    def _mod_inverse(self, a, p):
        """Modular inverse"""
        return pow(a, p-2, p)
    
    def _point_addition(self, P, Q):
        """Point addition"""
        if P is None:
            return Q
        if Q is None:
            return P
            
        x1, y1 = P
        x2, y2 = Q
        
        if x1 == x2 and y1 == y2:
            if y1 == 0:
                return None
            s = ((3 * x1 * x1 + self.a) * self._mod_inverse(2 * y1, self.p)) % self.p
        else:
            if x1 == x2:
                return None
            s = ((y2 - y1) * self._mod_inverse(x2 - x1, self.p)) % self.p
        
        x3 = (s * s - x1 - x2) % self.p
        y3 = (s * (x1 - x3) - y1) % self.p
        
        return (x3, y3)
    
    def _scalar_multiply(self, k, P):
        """Scalar multiplication"""
        result = None
        addend = P
        
        while k:
            if k & 1:
                result = self._point_addition(result, addend)
            addend = self._point_addition(addend, addend)
            k >>= 1
        
        return result
    
    def generate_keys(self):
        """Generate ECC key pair"""
        private_key = random.randint(1, self.n - 1)
        public_key = self._scalar_multiply(private_key, self.G)
        
        return {
            'private_key': private_key,
            'public_key': public_key
        }
    
    def encrypt_message(self, message, public_key):
        """Simple ECC encryption"""
        if isinstance(message, str):
            message = message.encode()
        
        k = random.randint(1, self.n - 1)
        R = self._scalar_multiply(k, self.G)
        
        S = self._scalar_multiply(k, public_key)
        if S is None:
            raise ValueError("Invalid encryption")
        
        secret_key = S[0] % (2**16)
        m = int.from_bytes(message, 'big') % (2**32)
        ciphertext = m ^ secret_key
        
        return {
            'R': R,
            'ciphertext': ciphertext
        }
    
    def decrypt_message(self, encrypted_data, private_key):
        """ECC decryption"""
        R = encrypted_data['R']
        ciphertext = encrypted_data['ciphertext']
        
        S = self._scalar_multiply(private_key, R)
        if S is None:
            raise ValueError("Invalid decryption")
        
        secret_key = S[0] % (2**16)
        plaintext_int = ciphertext ^ secret_key
        
        byte_length = (plaintext_int.bit_length() + 7) // 8
        plaintext_bytes = plaintext_int.to_bytes(byte_length, 'big') if byte_length > 0 else b''
        
        return plaintext_bytes.decode('utf-8', errors='ignore')
    
    def point_to_string(self, point):
        """Convert point to string"""
        if point is None:
            return None
        return f"{point[0]},{point[1]}"
    
    def string_to_point(self, point_str):
        """Convert string to point"""
        if not point_str:
            return None
        x_str, y_str = point_str.split(',')
        return (int(x_str), int(y_str))