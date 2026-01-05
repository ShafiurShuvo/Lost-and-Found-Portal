# crypto/hmac_custom.py
import hashlib

class CustomHMAC:
    """
    Custom HMAC-SHA256 implementation
    """
    
    def __init__(self, key):
        if isinstance(key, str):
            key = key.encode()
        self.key = key
    
    def _pad_key(self, key, block_size=64):
        """Pad key to block size"""
        if len(key) > block_size:
            key = hashlib.sha256(key).digest()
        if len(key) < block_size:
            key = key + b'\x00' * (block_size - len(key))
        return key
    
    def compute(self, message):
        """Compute HMAC-SHA256"""
        if isinstance(message, str):
            message = message.encode()
        
        block_size = 64
        key = self._pad_key(self.key, block_size)
        
        ipad = bytes([0x36] * block_size)
        opad = bytes([0x5C] * block_size)
        
        k_ipad = bytes(a ^ b for a, b in zip(key, ipad))
        k_opad = bytes(a ^ b for a, b in zip(key, opad))
        
        inner = hashlib.sha256(k_ipad + message).digest()
        outer = hashlib.sha256(k_opad + inner).digest()
        
        return outer.hex()
    
    def verify(self, message, hmac):
        """Verify HMAC"""
        return self.compute(message) == hmac