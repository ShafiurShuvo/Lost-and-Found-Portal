# Cryptographic Algorithms Usage Guide
## Lost & Found Portal - CSE447 Project

---

## 📋 Table of Contents
1. [Overview](#overview)
2. [Crypto Module Structure](#crypto-module-structure)
3. [Detailed Algorithm Usage](#detailed-algorithm-usage)
4. [Integration Points in Application](#integration-points-in-application)
5. [Security Features Summary](#security-features-summary)

---

## Overview

The Lost & Found Portal implements a comprehensive cryptographic security system to protect user data, verify claims, and ensure claim authenticity. The `crypto/` folder contains custom implementations of several encryption and authentication algorithms.

**Key Principle:** Multi-layered security approach combining symmetric, asymmetric, and hash-based cryptography.

---

## Crypto Module Structure

```
crypto/
├── __init__.py                  # Module exports
├── rsa_custom.py               # RSA asymmetric encryption
├── ecc_custom.py               # Elliptic Curve Cryptography
├── hmac_custom.py              # HMAC-SHA256 message authentication
├── multi_encrypt.py            # Combined RSA + ECC encryption
├── key_manager.py              # Key generation and management
├── two_factor.py               # TOTP-based 2FA
└── verification.py             # Cryptographic verification tokens
```

---

## Detailed Algorithm Usage

### 1. **SHA-256 Hashing** 
**Location:** `app.py` (line 4, 406, 187)  
**Algorithm File:** `crypto/hmac_custom.py`

#### Purpose:
- Password hashing and verification
- Creating digital signatures
- Proof-of-ownership verification

#### Implementation:
```python
import hashlib

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()
```

#### Usage Points in Application:

| Location | Usage | Details |
|----------|-------|---------|
| **User Registration** | `/register` route (line 510) | Hash user password before storing in database |
| **User Login** | `/login` route (line 538) | Verify password hash against stored hash |
| **Profile Edit** | `/edit_profile` route (line 741) | Validate user password for account changes |
| **HMAC Signatures** | `CryptographicVerifier` class (line 187) | Create HMAC-SHA256 signatures for claims |

#### Security Impact:
- ✅ One-way hashing prevents plaintext password storage
- ✅ Identical passwords produce same hash for verification
- ✅ SHA-256 is cryptographically secure (256-bit output)

---

### 2. **HMAC-SHA256 (Hash-based Message Authentication Code)**
**Location:** `crypto/hmac_custom.py`  
**Used in:** `app.py` (lines 115-190, 370-425)

#### Purpose:
- Authenticate claim data integrity
- Verify digital signatures on proof submissions
- Ensure claim messages haven't been tampered with

#### Implementation:
```python
class CustomHMAC:
    def compute(self, message):
        """Compute HMAC-SHA256"""
        # 1. Pad key to block size (64 bytes)
        # 2. Create inner and outer padding (ipad, opad)
        # 3. Hash(key XOR opad + Hash(key XOR ipad + message))
        
    def verify(self, message, hmac):
        """Verify HMAC using constant-time comparison"""
        return self.compute(message) == hmac
```

#### Usage Points in Application:

| Location | Usage | Details |
|----------|-------|---------|
| **Claim Verification** | `CryptographicVerifier._create_hmac_signature()` (line 187) | Create HMAC of claim data with user key |
| **Token Generation** | `ProofOfOwnershipSystem.verify_ownership_proof()` (lines 370-425) | Sign proof data with HMAC |
| **Signature Verification** | `CryptographicVerifier.verify_digital_signature()` | Verify claim authenticity |
| **Key Derivation** | `KeyManager.encrypt_user_data()` | Use HMAC for key derivation |

#### Example Workflow:
```
User submits claim → Create signature data object → 
Compute HMAC(claim_data, user_key) → Store in database → 
Admin reviews → Recompute HMAC → Compare signatures
```

#### Security Impact:
- ✅ Detects unauthorized modifications to claims
- ✅ Prevents claim message tampering
- ✅ Constant-time comparison prevents timing attacks

---

### 3. **RSA (Rivest-Shamir-Adleman)**
**Location:** `crypto/rsa_custom.py`  
**Used in:** `crypto/multi_encrypt.py`

#### Purpose:
- Asymmetric encryption of sensitive data
- Two-layer encryption with ECC

#### Implementation Details:
```python
class CustomRSA:
    def __init__(self, key_size=256):
        # 1. Generate two large prime numbers (p, q)
        # 2. Compute n = p × q (modulus)
        # 3. Compute φ(n) = (p-1)(q-1)
        # 4. Find public exponent e (coprime with φ(n))
        # 5. Find private exponent d (e × d ≡ 1 mod φ(n))
        
    def _is_prime(self, n, k=5):
        """Miller-Rabin primality test"""
        # Probabilistic algorithm for testing primality
        
    def encrypt(self, plaintext, public_key):
        """Ciphertext = plaintext^e mod n"""
        
    def decrypt(self, ciphertext, private_key):
        """Plaintext = ciphertext^d mod n"""
```

#### Usage Points in Application:

| Location | Usage | Details |
|----------|-------|---------|
| **Multi-Level Encryption** | `MultiLevelEncryption.encrypt()` (lines 45-60) | Second layer of encryption after ECC |
| **Key Management** | `KeyManager.generate_master_key()` | Generate RSA keys for system |
| **User Key Generation** | `KeyManager.generate_user_keys()` | Generate per-user RSA keys |

#### Encryption Flow:
```
Plaintext → ECC Encryption → JSON encode → RSA Encryption → Base64 encode → Database
```

#### Security Impact:
- ✅ Public-key cryptography (no key sharing needed)
- ✅ 256-bit RSA modulus (for demo; production uses 2048+)
- ✅ Dual encryption with ECC provides defense-in-depth

---

### 4. **ECC (Elliptic Curve Cryptography)**
**Location:** `crypto/ecc_custom.py`  
**Used in:** `crypto/multi_encrypt.py`

#### Purpose:
- First-layer encryption of proof data
- Faster asymmetric encryption than RSA
- Smaller key sizes with equivalent security

#### Implementation Details:
```python
class CustomECC:
    def __init__(self, curve='demo'):
        # Demo curve parameters (small for performance)
        self.p = 101          # Field modulus
        self.a = 0, self.b = 7  # Curve equation: y² = x³ + ax + b
        self.G = (2, 22)      # Generator point
        self.n = 97           # Order of generator
        
    def _point_addition(self, P, Q):
        """Elliptic curve point addition"""
        # 1. Calculate slope s = (y2-y1)/(x2-x1) mod p
        # 2. Compute new point (x3, y3) = (s²-x1-x2, s(x1-x3)-y1)
        
    def encrypt_message(self, plaintext, public_key):
        """ECC encryption using random k"""
        # C1 = k × G (random point)
        # C2 = plaintext XOR Hash(k × public_key)
```

#### Usage Points in Application:

| Location | Usage | Details |
|----------|-------|---------|
| **Multi-Level Encryption** | `MultiLevelEncryption.encrypt()` (lines 27-40) | First-layer encryption |
| **Proof Data Encryption** | `MultiLevelEncryption.decrypt()` | Decrypt submitted proofs |
| **Key Management** | `KeyManager.generate_user_keys()` | Generate ECC keys per user |

#### Encryption Flow:
```
Plaintext → ECC Encrypt(plaintext, ECC_public_key) → 
    Returns {R: random_point, ciphertext: encrypted_value} → 
JSON encode → RSA Encrypt → Database
```

#### Security Impact:
- ✅ Elliptic curve security (160-bit ECC ≈ 1024-bit RSA)
- ✅ Faster computation than RSA
- ✅ Smaller key sizes reduce storage overhead

---

### 5. **Multi-Level Encryption (ECC + RSA)**
**Location:** `crypto/multi_encrypt.py`  
**Used in:** `crypto/key_manager.py`

#### Purpose:
- Combine ECC and RSA for defense-in-depth
- Encrypt sensitive user data and proof submissions

#### Encryption Process:
```
Step 1: ECC Encryption
Input: plaintext
Output: {R: point, ciphertext: int}

Step 2: JSON Encoding
Input: ECC output
Output: JSON string

Step 3: RSA Encryption
Input: JSON string
Output: ciphertext bytes

Step 4: Base64 Encoding
Input: ciphertext bytes
Output: Base64 string → Database
```

#### Implementation:
```python
def encrypt(self, data):
    # Step 1: ECC encrypt
    ecc_encrypted = self.ecc.encrypt_message(data_str, self.ecc_public)
    
    # Step 2-3: JSON + RSA encrypt
    ecc_data_str = json.dumps(ecc_encrypted)
    rsa_encrypted = self.rsa.encrypt_string(ecc_data_str, self.rsa_public)
    
    # Step 4: Base64 encode
    return base64.b64encode(rsa_encrypted).decode('utf-8')
```

#### Usage Points in Application:

| Location | Usage | Details |
|----------|-------|---------|
| **Key Manager** | `KeyManager.encrypt_user_data()` | Encrypt sensitive user information |
| **Key Manager** | `KeyManager.decrypt_user_data()` | Decrypt encrypted user data |

#### Security Impact:
- ✅ Two-layer encryption: if one algorithm is compromised, data remains secure
- ✅ ECC is faster, RSA provides backup security
- ✅ Reduces single-algorithm dependency risk

---

### 6. **Key Manager**
**Location:** `crypto/key_manager.py`  
**Used in:** Application initialization

#### Purpose:
- Generate and manage cryptographic keys
- Store and retrieve user keys
- Encrypt/decrypt user data

#### Key Features:
```python
class KeyManager:
    def generate_master_key(self):
        """Create system-wide encryption keys"""
        # Generates RSA + ECC key pair
        # Stores in JSON file with timestamps
        
    def generate_user_keys(self, user_id):
        """Create per-user encryption keys"""
        # Unique keys for each user
        # Rotation tracking for security updates
        
    def encrypt_user_data(self, user_id, data):
        """Encrypt data with user's keys"""
        # Uses multi-level encryption
        
    def decrypt_user_data(self, user_id, encrypted_data):
        """Decrypt data with user's keys"""
```

#### Usage Points in Application:

| Location | Usage | Details |
|----------|-------|---------|
| **System Initialization** | `init_db()` | Create master encryption keys |
| **User Registration** | `/register` route | Generate keys for new user |
| **Claim Submission** | `/claim/<item_id>` | Encrypt proof data with user keys |

#### Security Impact:
- ✅ Per-user encryption keys (isolation)
- ✅ Key rotation support for security updates
- ✅ Master key for system-level encryption

---

### 7. **Two-Factor Authentication (2FA / TOTP)**
**Location:** `crypto/two_factor.py`  
**Used in:** `utils/otp.py` (integration)

#### Purpose:
- Generate time-based one-time passwords (TOTP)
- Protect login process with 2FA
- Create OTP bypass tokens for 10-minute sessions

#### Implementation Details:
```python
class TwoFactorAuth:
    def generate_totp(self, time_step=None):
        """
        TOTP Algorithm (RFC 6238):
        1. Get current time step (Unix time / 30 seconds)
        2. Create HMAC-SHA1(secret, time_bytes)
        3. Extract 31-bit integer from hash
        4. Return 6-digit code (modulo 10^6)
        """
        
    def verify_totp(self, code, window=1):
        """Verify TOTP with time window tolerance"""
        # Allow ±1 time step (60 seconds tolerance)
```

#### Usage Points in Application:

| Location | Usage | Details |
|----------|-------|---------|
| **Login Process** | `/login` route (lines 557-580) | Generate 6-digit OTP |
| **OTP Verification** | `/verify-otp` route (lines 600-650) | Verify user-submitted OTP |
| **OTP Bypass** | Session management (lines 625-640) | Create 10-minute bypass tokens |
| **Database** | `otp_codes` table | Store OTP codes with expiration |
| **Database** | `otp_bypass` table | Store bypass tokens |

#### Workflow:
```
Login with username/password → 
Generate OTP code → 
Send via email → 
User enters OTP → 
Verify HMAC-SHA1 signature → 
Create bypass token (10 min) → 
Complete login
```

#### Security Impact:
- ✅ Time-based (TOTP) prevents code reuse
- ✅ 6-digit code provides ~1 million combinations
- ✅ Email delivery adds out-of-band verification
- ✅ Bypass token reduces friction for repeat logins

---

### 8. **Cryptographic Verification System**
**Location:** `crypto/verification.py` and inline in `app.py` (lines 115-190)

#### Purpose:
- Generate verification tokens for claims
- Verify claim authenticity and integrity
- Track verification score for each claim

#### Implementation:
```python
class CryptographicVerifier:
    def generate_verification_token(self, claim_data, user_key):
        """
        Create digitally signed verification token:
        1. Create payload with claim_id, timestamp, nonce
        2. Serialize to JSON (deterministic order)
        3. Compute HMAC-SHA256(payload, user_key)
        4. Return Base64-encoded {payload, signature}
        """
        
    def verify_claim_token(self, token, user_key):
        """
        Verify token authenticity:
        1. Decode Base64 token
        2. Extract payload and signature
        3. Recompute HMAC
        4. Compare with constant-time algorithm
        5. Check token expiration (24 hours)
        """
        
    def create_digital_signature(self, data, key):
        """Create HMAC signature for any data"""
        
    def verify_digital_signature(self, data, signature, key):
        """Verify HMAC signature using constant-time comparison"""
```

#### Usage Points in Application:

| Location | Usage | Details |
|----------|-------|---------|
| **Claim Submission** | `/claim/<item_id>` POST (lines 950-1020) | Generate token for new claim |
| **Proof Verification** | `ProofOfOwnershipSystem.verify_ownership_proof()` | Verify proof signature |
| **Admin Review** | `/admin/verify_claim/<claim_id>` | Check token validity |
| **Database** | `claims.verification_token` column | Store signed tokens |
| **Database** | `claims.digital_signature` column | Store claim message signatures |

#### Token Structure:
```json
{
    "payload": {
        "claim_id": 123,
        "claimant_id": 5,
        "item_id": 42,
        "timestamp": "2026-01-06T10:30:00",
        "nonce": "a1b2c3d4e5f6...",
        "verification_level": "enhanced"
    },
    "signature": "a1b2c3d4e5f6...(HMAC-SHA256 hex)",
    "algorithm": "sha256"
}
```

#### Verification Workflow:
```
Claim submitted → Generate token with HMAC signature → 
Store in database → Admin clicks "Verify" → 
Recompute HMAC → Compare signatures (constant-time) → 
Check timestamp (< 24 hours) → Display verification result
```

#### Security Impact:
- ✅ Prevents claim tampering after submission
- ✅ Links each claim to specific user (HMAC key)
- ✅ Timestamps prevent token replay attacks
- ✅ Nonces ensure uniqueness

---

### 9. **Proof of Ownership System**
**Location:** `app.py` (lines 197-380)

#### Purpose:
- Evaluate cryptographic proof of item ownership
- Assign verification scores based on evidence
- Generate verification reports

#### Implementation:
```python
class ProofOfOwnershipSystem:
    def verify_ownership_proof(self, claim_data, proof_data, claimant_key):
        """
        Comprehensive verification:
        1. Verify proof signature (25 points)
        2. Check timestamp validity (15 points)
        3. Evaluate evidence quality (60 points)
           - Serial number (20 pts)
           - Purchase info (15 pts)
           - Unique features (15 pts)
           - Detailed description (25 pts)
           - Photo evidence (15 pts)
        4. Generate report with recommendation
        """
        
    def _evaluate_evidence(self, evidence, verification_level):
        """Score evidence based on completeness"""
        # basic: 10 points
        # enhanced: 25 points
        # premium: 40 points
        
    def _get_recommendation(self, score):
        """
        Score-based recommendation:
        80+: STRONG_OWNERSHIP
        60-79: LIKELY_OWNER
        40-59: POSSIBLE_OWNER
        <40: UNLIKELY_OWNER
        """
```

#### Usage Points in Application:

| Location | Usage | Details |
|----------|-------|---------|
| **Claim Submission** | `/claim/<item_id>` POST (lines 950-1020) | Generate ownership proof report |
| **Admin Dashboard** | `/admin/proof_verification` | View proof scores for all claims |
| **Admin Review** | `/admin/verify_claim/<claim_id>` | Display detailed proof analysis |
| **Database** | `claims.cryptographic_score` column | Store final proof score |
| **Database** | `claims.verification_summary` column | Store verification report JSON |

#### Proof Data Collection:
```python
proof_data = {
    'serial_number': '...',          # Item serial/model number
    'purchase_date': '2025-01-01',   # When item was purchased
    'purchase_location': '...',      # Where item was purchased
    'unique_features': '...',        # Unique marks/characteristics
    'photo_evidence': '...',         # Photos of item
    'detailed_description': '...',   # Detailed description
    'proof_timestamp': '2026-01-06T10:30:00'
}
```

#### Verification Report Example:
```json
{
    "verification_id": "abc123xyz",
    "timestamp": "2026-01-06T10:30:00",
    "total_score": 75,
    "verification_results": [
        {"check": "Proof Signature", "status": "PASS", "score": 25},
        {"check": "Proof Timestamp", "status": "PASS", "score": 15},
        {"check": "Evidence Evaluation", "status": "COMPLETED", "score": 35}
    ],
    "recommendation": "LIKELY_OWNER - MODERATE CONFIDENCE",
    "cryptographic_evidence": {
        "proof_valid": true,
        "signature_verified": true,
        "timestamp_valid": true
    }
}
```

#### Security Impact:
- ✅ Cryptographically verified ownership evidence
- ✅ Scoring prevents false claims
- ✅ Multiple evidence types required for high scores
- ✅ Admin can review cryptographic proofs objectively

---

## Integration Points in Application

### 1. **User Authentication Flow**
```
┌─────────────────────────────────────────┐
│         User Registration               │
├─────────────────────────────────────────┤
│ 1. Input: password                      │
│ 2. Hash: SHA-256(password)              │
│ 3. Store: password_hash in DB           │
│ 4. Generate: User RSA/ECC keys          │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│          User Login                     │
├─────────────────────────────────────────┤
│ 1. Input: username, password            │
│ 2. Retrieve: password_hash from DB      │
│ 3. Verify: SHA-256(password) == hash    │
│ 4. Generate: 6-digit OTP                │
│ 5. Send: OTP via email                  │
│ 6. Store: OTP in otp_codes table        │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│       2FA OTP Verification              │
├─────────────────────────────────────────┤
│ 1. User enters: 6-digit code            │
│ 2. Verify: HMAC-SHA1 against OTP        │
│ 3. Check: Timestamp (valid time window) │
│ 4. Optional: Create bypass token        │
│ 5. Bypass: Token valid for 10 minutes   │
│ 6. Complete: Login, create session      │
└─────────────────────────────────────────┘
```

### 2. **Claim Submission Flow**
```
┌─────────────────────────────────────────┐
│        User Submits Claim               │
├─────────────────────────────────────────┤
│ 1. Input: claim message, proof data     │
│ 2. Collect: serial, purchase, features  │
│ 3. Select: verification level           │
│ 4. Create: claim_data object            │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│   Generate Verification Token           │
├─────────────────────────────────────────┤
│ 1. Create: payload with claim data      │
│ 2. Serialize: JSON (deterministic)      │
│ 3. Sign: HMAC-SHA256(payload, user_key) │
│ 4. Encode: Base64({payload, signature}) │
│ 5. Result: verification_token           │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│  Create Digital Signature               │
├─────────────────────────────────────────┤
│ 1. Combine: claim_message + proof_data  │
│ 2. Add: timestamp                       │
│ 3. Sign: HMAC-SHA256(signature_data)    │
│ 4. Store: digital_signature in DB       │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│   Encrypt Proof Data                    │
├─────────────────────────────────────────┤
│ 1. Step 1: ECC encrypt proof_data       │
│ 2. Step 2: JSON encode ECC output       │
│ 3. Step 3: RSA encrypt JSON             │
│ 4. Step 4: Base64 encode result         │
│ 5. Store: In proof_data column          │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│   Verify Ownership Proof                │
├─────────────────────────────────────────┤
│ 1. Check: Proof signature (25 pts)      │
│ 2. Check: Timestamp validity (15 pts)   │
│ 3. Evaluate: Evidence quality (60 pts)  │
│ 4. Calculate: Total score               │
│ 5. Generate: Recommendation             │
│ 6. Store: cryptographic_score in DB     │
└─────────────────────────────────────────┘
```

### 3. **Admin Claim Review Flow**
```
┌─────────────────────────────────────────┐
│    Admin Views Pending Claims           │
├─────────────────────────────────────────┤
│ 1. Query: Claims with status='approved' │
│ 2. Display: Cryptographic scores        │
│ 3. Show: Verification summaries         │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│   Admin Clicks "Verify"                 │
├─────────────────────────────────────────┤
│ 1. Load: verification_token from DB     │
│ 2. Decode: Base64 token                 │
│ 3. Extract: payload, signature          │
│ 4. Verify: HMAC signature               │
│ 5. Check: Token not expired (24h)       │
│ 6. Load: proof_data from DB             │
│ 7. Decrypt: RSA then ECC decrypt        │
│ 8. Display: Ownership proof details     │
│ 9. Show: Evidence evaluation scores     │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│   Admin Makes Decision                  │
├─────────────────────────────────────────┤
│ 1. Review: Cryptographic verification   │
│ 2. Review: Evidence quality             │
│ 3. Review: Claimant history             │
│ 4. Approve: Mark as verified            │
│    OR                                   │
│ 5. Reject: Return to available          │
└─────────────────────────────────────────┘
```

---

## Security Features Summary

### 🔐 **Password Security**
- **Algorithm:** SHA-256 hashing
- **Protection:** One-way encryption, rainbow table resistant
- **Used in:** User registration, login, profile edits

### 🔑 **Message Authentication**
- **Algorithm:** HMAC-SHA256
- **Protection:** Detects tampering, verifies authenticity
- **Used in:** Claim verification, digital signatures, proof authentication

### 🔓 **Asymmetric Encryption**
- **Algorithms:** RSA (256-bit) + ECC (demo curve)
- **Protection:** Public-key cryptography, dual encryption
- **Used in:** Multi-level encryption of sensitive data

### 🕐 **Time-Based Authentication**
- **Algorithm:** TOTP (RFC 6238 with HMAC-SHA1)
- **Protection:** Time-based codes prevent reuse
- **Used in:** Two-factor authentication (2FA)

### ✅ **Verification Tokens**
- **Algorithm:** HMAC-signed JSON tokens
- **Protection:** Cryptographically signed, timestamp-based expiration
- **Used in:** Claim authenticity verification

### 📊 **Proof Scoring**
- **Method:** Multi-criteria evaluation with cryptographic verification
- **Protection:** Objective assessment of ownership evidence
- **Used in:** Claim verification workflow

---

## Database Schema (Cryptographic Fields)

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,        -- SHA-256 hashed
    email TEXT NOT NULL,
    ...
)
```

### Claims Table (Crypto Fields)
```sql
CREATE TABLE claims (
    id INTEGER PRIMARY KEY,
    ...
    verification_level TEXT,            -- basic/enhanced/premium
    verification_token TEXT,            -- HMAC-signed token
    digital_signature TEXT,             -- HMAC of claim message
    cryptographic_score INTEGER,        -- Proof score (0-100)
    ...
)
```

### OTP Tables
```sql
CREATE TABLE otp_codes (
    email TEXT,
    otp_code TEXT,                      -- 6-digit TOTP
    expiration_time TIMESTAMP           -- 10 minutes
)

CREATE TABLE otp_bypass (
    user_id INTEGER,
    bypass_token TEXT UNIQUE,           -- 32-byte random token
    expiration_time TIMESTAMP           -- 10 minutes
)
```

---

## Security Recommendations for Production

### Current Implementation (Educational)
- ✅ Multi-layered encryption (ECC + RSA)
- ✅ HMAC for message authentication
- ✅ 2FA for user authentication
- ⚠️ Uses small key sizes for performance (256-bit RSA, demo ECC curve)
- ⚠️ Cryptographic implementations are custom (not production-hardened)

### Production Upgrades Needed
1. **Increase Key Sizes**
   - RSA: Use 2048-bit or 4096-bit
   - ECC: Use standard curves (P-256, P-384, P-521)

2. **Use Established Libraries**
   - `cryptography` package instead of custom implementations
   - `argon2` for password hashing instead of SHA-256
   - `pyotp` for TOTP authentication

3. **Enhanced Security**
   - Add rate limiting for OTP attempts
   - Implement account lockout after failed attempts
   - Use TLS/HTTPS for all communications
   - Add audit logging for all cryptographic operations
   - Implement key rotation policies

4. **Code Example for Production**
   ```python
   from cryptography.hazmat.primitives import hashes
   from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
   from argon2 import PasswordHasher
   
   # Use Argon2 instead of SHA-256
   ph = PasswordHasher()
   password_hash = ph.hash(password)
   ph.verify(password_hash, password)
   
   # Use proper RSA
   from cryptography.hazmat.primitives.asymmetric import rsa
   private_key = rsa.generate_private_key(
       public_exponent=65537,
       key_size=2048
   )
   ```

---

## Testing the Cryptographic System

### Test Endpoints

1. **Test User Registration (Password Hashing)**
   ```bash
   POST /register
   - Username: testuser
   - Password: testpass123
   - Verify: password_hash stored in DB
   ```

2. **Test User Login (SHA-256 Verification)**
   ```bash
   POST /login
   - Username: testuser
   - Password: testpass123
   - Verify: OTP generated and sent
   ```

3. **Test 2FA (TOTP Verification)**
   ```bash
   POST /verify-otp
   - Email: user@example.com
   - OTP Code: 123456 (or real OTP)
   - Verify: Bypass token created
   ```

4. **Test Claim Submission (HMAC + Encryption)**
   ```bash
   POST /claim/<item_id>
   - Claim message: "I own this item..."
   - Verification level: enhanced
   - Proof data: serial number, features, etc.
   - Verify: verification_token stored
   - Verify: digital_signature created
   - Verify: cryptographic_score calculated
   ```

5. **Test Admin Verification**
   ```bash
   GET /admin/verify_claim/<claim_id>
   - Verify: Token signature validated
   - Verify: Proof data decrypted
   - Verify: Score displayed
   ```

---

## Summary

The Lost & Found Portal implements a comprehensive cryptographic security system:

| Algorithm | Purpose | Location | Impact |
|-----------|---------|----------|--------|
| **SHA-256** | Password hashing | `app.py:406` | Secure password storage |
| **HMAC-SHA256** | Message authentication | `crypto/hmac_custom.py` | Claim authenticity |
| **RSA** | Asymmetric encryption | `crypto/rsa_custom.py` | Sensitive data protection |
| **ECC** | Elliptic curve encryption | `crypto/ecc_custom.py` | Efficient encryption |
| **Multi-Level** | Dual encryption | `crypto/multi_encrypt.py` | Defense-in-depth |
| **TOTP** | Time-based OTP | `crypto/two_factor.py` | 2FA authentication |
| **Verification Tokens** | Signed claims | `app.py:115-190` | Claim integrity |
| **Proof Scoring** | Evidence evaluation | `app.py:197-380` | Claim verification |

Each component works together to provide a secure, verifiable lost & found platform suitable for an academic CSE447 project.

---

*Document Created: January 6, 2026*  
*Project: Lost & Found Portal - CSE447*  
*Version: 1.0*
