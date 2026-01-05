# crypto/rsa_custom.py
import random
import math

class CustomRSA:
    """
    Custom RSA implementation from scratch
    """
    
    def __init__(self, key_size=256):  # Smaller for demo speed
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        self.n = None
        
    def _is_prime(self, n, k=5):
        """Miller-Rabin primality test"""
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False
            
        d = n - 1
        r = 0
        while d % 2 == 0:
            d //= 2
            r += 1
            
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
                
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
                
        return True
    
    def _generate_large_prime(self):
        """Generate a large prime number"""
        while True:
            num = random.getrandbits(self.key_size // 2)
            num |= (1 << (self.key_size // 2 - 1)) | 1
            
            if self._is_prime(num, k=5):
                return num
    
    def _extended_gcd(self, a, b):
        """Extended Euclidean Algorithm"""
        if a == 0:
            return (b, 0, 1)
        
        gcd, x1, y1 = self._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return (gcd, x, y)
    
    def _mod_inverse(self, a, m):
        """Modular inverse"""
        gcd, x, y = self._extended_gcd(a, m)
        if gcd != 1:
            raise ValueError(f"No modular inverse for {a} mod {m}")
        return x % m
    
    def generate_keys(self):
        """Generate RSA public/private key pair"""
        p = self._generate_large_prime()
        q = self._generate_large_prime()
        
        while p == q:
            q = self._generate_large_prime()
        
        self.n = p * q
        phi = (p - 1) * (q - 1)
        
        e = 65537
        while math.gcd(e, phi) != 1:
            e += 2
        
        d = self._mod_inverse(e, phi)
        
        self.public_key = (e, self.n)
        self.private_key = (d, self.n, p, q)
        
        return {
            'public_key': self.public_key,
            'private_key': self.private_key,
            'p': p,
            'q': q,
            'phi': phi
        }
    
    def encrypt(self, message_int, public_key=None):
        """RSA encryption: c = m^e mod n"""
        if public_key:
            e, n = public_key
        else:
            e, n = self.public_key
        
        if message_int >= n:
            raise ValueError("Message too large for RSA")
        
        return pow(message_int, e, n)
    
    def decrypt(self, ciphertext_int, private_key=None):
        """RSA decryption with CRT optimization"""
        if private_key:
            d, n, p, q = private_key
        else:
            d, n, p, q = self.private_key
        
        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = self._mod_inverse(q, p)
        
        m1 = pow(ciphertext_int, dp, p)
        m2 = pow(ciphertext_int, dq, q)
        
        h = (qinv * (m1 - m2)) % p
        m = m2 + h * q
        
        return m
    
    def encrypt_bytes(self, message_bytes, public_key=None):
        """Encrypt bytes"""
        m = int.from_bytes(message_bytes, 'big')
        c = self.encrypt(m, public_key)
        return c.to_bytes((c.bit_length() + 7) // 8, 'big')
    
    def decrypt_bytes(self, ciphertext_bytes, private_key=None):
        """Decrypt to bytes"""
        c = int.from_bytes(ciphertext_bytes, 'big')
        m = self.decrypt(c, private_key)
        return m.to_bytes((m.bit_length() + 7) // 8, 'big')
    
    def encrypt_string(self, text, public_key=None):
        """Encrypt a string"""
        max_len = (self.key_size // 8) - 11
        if len(text) > max_len:
            raise ValueError(f"Text too long. Max {max_len} characters")
        
        padding = random.getrandbits(64).to_bytes(8, 'big')
        message = padding + text.encode() + padding
        return self.encrypt_bytes(message, public_key)
    
    def decrypt_string(self, ciphertext, private_key=None):
        """Decrypt to string"""
        decrypted = self.decrypt_bytes(ciphertext, private_key)
        if len(decrypted) >= 16:
            return decrypted[8:-8].decode('utf-8', errors='ignore')
        return decrypted.decode('utf-8', errors='ignore')