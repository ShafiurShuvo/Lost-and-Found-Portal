# database.py - CORRECTED VERSION
import sqlite3
import json
import hashlib
from datetime import datetime
from crypto.key_manager import KeyManager

class EncryptedDatabase:
    """
    Database with automatic encryption/decryption
    """
    
    def __init__(self, db_name='lost_found.db'):
        self.db_name = db_name
        self.key_manager = KeyManager()
        self.init_db()
    
    def get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_name)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_db(self):
        """Initialize database tables"""
        conn = self.get_connection()
        c = conn.cursor()
        
        # Users table
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                encrypted_data TEXT NOT NULL,
                data_signature TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        # Items table
        c.execute('''
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                encrypted_data TEXT NOT NULL,
                data_signature TEXT NOT NULL,
                status TEXT DEFAULT 'available',
                photo_path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Claims table - FIXED: Removed ALTER TABLE from CREATE
        c.execute('''
            CREATE TABLE IF NOT EXISTS claims (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL,
                claimant_id INTEGER NOT NULL,
                encrypted_data TEXT NOT NULL,
                data_signature TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                reviewed_by INTEGER,
                reviewed_at TIMESTAMP,
                verification_level TEXT DEFAULT 'basic',
                admin_verified BOOLEAN DEFAULT 0,
                verification_token TEXT,
                digital_signature TEXT,
                verification_summary TEXT,
                cryptographic_score INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE CASCADE,
                FOREIGN KEY (claimant_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (reviewed_by) REFERENCES users (id) ON DELETE SET NULL
            )
        ''')
        
        # User reputation
        c.execute('''
            CREATE TABLE IF NOT EXISTS user_reputation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                encrypted_data TEXT NOT NULL,
                data_signature TEXT NOT NULL,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Now add any missing columns (ALTER TABLE should be separate)
        self._add_missing_columns()
        
        # Create admin user if not exists
        self._create_admin_user()
        
        print("Database initialized successfully!")
    
    def _add_missing_columns(self):
        """Add any missing columns to existing tables"""
        conn = self.get_connection()
        c = conn.cursor()
        
        # Check and add columns for claims table
        c.execute("PRAGMA table_info(claims)")
        columns = [col[1] for col in c.fetchall()]
        
        if 'verification_token' not in columns:
            c.execute("ALTER TABLE claims ADD COLUMN verification_token TEXT")
        
        if 'digital_signature' not in columns:
            c.execute("ALTER TABLE claims ADD COLUMN digital_signature TEXT")
        
        if 'verification_summary' not in columns:
            c.execute("ALTER TABLE claims ADD COLUMN verification_summary TEXT")
        
        if 'cryptographic_score' not in columns:
            c.execute("ALTER TABLE claims ADD COLUMN cryptographic_score INTEGER DEFAULT 0")
        
        conn.commit()
        conn.close()
    
    # ... rest of your existing methods remain the same until create_claim_with_verification ...
    
    def create_claim_with_verification(self, item_id, claimant_id, claim_message, verification_level='basic'):
        """Create claim with cryptographic verification - FIXED VERSION"""
        claim_data = {
            'item_id': item_id,
            'claimant_id': claimant_id,
            'claim_message': claim_message,
            'verification_level': verification_level,
            'created_at': datetime.now().isoformat()
        }
        
        # Get user data
        user = self.get_user_by_id(claimant_id)  # Fixed: using self.
        if not user:
            print(f"User {claimant_id} not found")
            return None
        
        # Get the username for encryption
        username = user['username']
        
        # Use the existing key manager for encryption
        encrypted_data = self.key_manager.encrypt_user_data(username, claim_data)
        signature = self.key_manager.sign_data(claim_data, username)
        
        # Generate verification token using hash
        import hashlib
        import time
        import secrets
        
        # Create a simple verification token for demonstration
        # In production, use proper cryptographic tokens
        token_data = f"{claimant_id}_{item_id}_{time.time()}_{secrets.token_hex(8)}"
        verification_token = hashlib.sha256(token_data.encode()).hexdigest()
        
        # Create digital signature
        signature_data = f"{claimant_id}:{item_id}:{claim_message}"
        digital_signature = hashlib.sha256(signature_data.encode()).hexdigest()
        
        # Calculate cryptographic score (simplified for demo)
        cryptographic_score = 50  # Base score
        if verification_level == 'advanced':
            cryptographic_score = 80
        elif verification_level == 'admin':
            cryptographic_score = 100
        
        conn = self.get_connection()
        c = conn.cursor()
        
        try:
            # Insert claim with all verification data
            c.execute('''
                INSERT INTO claims (
                    item_id, claimant_id, encrypted_data, data_signature,
                    verification_level, verification_token, digital_signature,
                    cryptographic_score, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
            ''', (
                item_id, claimant_id, encrypted_data, signature,
                verification_level, verification_token, digital_signature,
                cryptographic_score
            ))
            
            claim_id = c.lastrowid
            
            # Update verification token with claim ID
            updated_token_data = f"{verification_token}_{claim_id}"
            final_verification_token = hashlib.sha256(updated_token_data.encode()).hexdigest()
            
            c.execute('''
                UPDATE claims 
                SET verification_token = ? 
                WHERE id = ?
            ''', (final_verification_token, claim_id))
            
            # Update item status
            c.execute('''
                UPDATE items 
                SET status = 'claimed' 
                WHERE id = ?
            ''', (item_id,))
            
            conn.commit()
            
            print(f"Created claim {claim_id} with verification token: {final_verification_token[:16]}...")
            return claim_id
            
        except Exception as e:
            print(f"Error creating claim: {e}")
            conn.rollback()
            return None
        finally:
            conn.close()
    
    # If you need a separate verifier class, add it:
    class Verifier:
        """Simple verifier class for demonstration"""
        
        @staticmethod
        def generate_verification_token(data, key):
            """Generate verification token"""
            import hashlib
            import json
            import time
            
            data_str = json.dumps(data, sort_keys=True)
            timestamp = str(int(time.time()))
            combined = f"{data_str}:{timestamp}:{key}"
            return hashlib.sha256(combined.encode()).hexdigest()
        
        @staticmethod
        def create_digital_signature(data, key):
            """Create digital signature"""
            import hashlib
            import json
            
            data_str = json.dumps(data, sort_keys=True)
            combined = f"{data_str}:{key}"
            return hashlib.sha256(combined.encode()).hexdigest()

# Usage example:
if __name__ == "__main__":
    db = EncryptedDatabase()
    
    # Test creating a claim
    # First create test users and item
    user1_id = db.create_user("testuser", "test@example.com", "hash123", "Test User")
    item1_id = db.create_item(user1_id, "Test Item", "Description", "Location", "lost", "electronics")
    
    if user1_id and item1_id:
        claim_id = db.create_claim_with_verification(
            item_id=item1_id,
            claimant_id=user1_id,
            claim_message="This is my item, I lost it yesterday",
            verification_level='basic'
        )
        
        if claim_id:
            print(f"Claim created successfully with ID: {claim_id}")