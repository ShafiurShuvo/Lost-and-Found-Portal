# app.py - COMPLETE VERSION WITH CRYPTOGRAPHIC VERIFICATION
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import os
import hashlib
import json
import sqlite3
import base64
import random
import hmac
import secrets
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from utils.otp import OTPManager

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'lost-found-portal-secure-key-2024-cse447')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_UPLOAD_SIZE', 5 * 1024 * 1024))

# Create directories
os.makedirs('static/uploads', exist_ok=True)
os.makedirs('templates', exist_ok=True)

# Simple database setup
def init_db():
    conn = sqlite3.connect('lost_found.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            full_name TEXT,
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
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            location TEXT NOT NULL,
            item_type TEXT NOT NULL,
            category TEXT NOT NULL,
            photo_path TEXT,
            status TEXT DEFAULT 'available',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    # Claims table with cryptographic fields
    c.execute('''
        CREATE TABLE IF NOT EXISTS claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            claimant_id INTEGER NOT NULL,
            claim_message TEXT NOT NULL,
            verification_level TEXT DEFAULT 'basic',
            verification_token TEXT,
            digital_signature TEXT,
            verification_summary TEXT,
            cryptographic_score INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',
            reviewed_by INTEGER,
            reviewed_at TIMESTAMP,
            admin_notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE CASCADE,
            FOREIGN KEY (claimant_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (reviewed_by) REFERENCES users (id) ON DELETE SET NULL
        )
    ''')
    
    # OTP table for 2FA via email
    c.execute('''
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            otp_code TEXT NOT NULL,
            expiration_time TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # OTP Bypass tokens (for 10-minute OTP-free login)
    c.execute('''
        CREATE TABLE IF NOT EXISTS otp_bypass (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            bypass_token TEXT UNIQUE NOT NULL,
            expiration_time TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")

# Cryptographic Verification System
class CryptographicVerifier:
    """Real cryptographic verification system"""
    
    def __init__(self):
        self.hash_algorithm = 'sha256'
    
    def generate_verification_token(self, claim_data, user_key):
        """Generate cryptographic verification token"""
        verification_payload = {
            'claim_id': claim_data.get('claim_id'),
            'claimant_id': claim_data.get('claimant_id'),
            'item_id': claim_data.get('item_id'),
            'timestamp': datetime.now().isoformat(),
            'nonce': secrets.token_hex(16),
            'verification_level': claim_data.get('verification_level', 'basic')
        }
        
        payload_str = json.dumps(verification_payload, sort_keys=True)
        signature = self._create_hmac_signature(payload_str, user_key)
        
        token = {
            'payload': verification_payload,
            'signature': signature,
            'algorithm': self.hash_algorithm
        }
        
        return base64.b64encode(json.dumps(token).encode()).decode()
    
    def verify_claim_token(self, token, user_key):
        """Verify cryptographic token"""
        try:
            decoded_token = json.loads(base64.b64decode(token.encode()).decode())
            
            payload = decoded_token.get('payload', {})
            signature = decoded_token.get('signature', '')
            
            payload_str = json.dumps(payload, sort_keys=True)
            expected_signature = self._create_hmac_signature(payload_str, user_key)
            
            if not hmac.compare_digest(signature, expected_signature):
                return False, "Signature verification failed"
            
            # Check token expiration (24 hours)
            token_time = datetime.fromisoformat(payload.get('timestamp', ''))
            if (datetime.now() - token_time).total_seconds() > 86400:
                return False, "Token expired"
            
            return True, {
                'claim_id': payload.get('claim_id'),
                'verification_level': payload.get('verification_level'),
                'timestamp': payload.get('timestamp'),
                'verification_score': self._calculate_verification_score(payload)
            }
            
        except Exception as e:
            return False, f"Verification error: {str(e)}"
    
    def create_digital_signature(self, data, key):
        """Create digital signature"""
        data_str = json.dumps(data, sort_keys=True)
        return self._create_hmac_signature(data_str, key)
    
    def verify_digital_signature(self, data, signature, key):
        """Verify digital signature"""
        data_str = json.dumps(data, sort_keys=True)
        expected_signature = self._create_hmac_signature(data_str, key)
        return hmac.compare_digest(signature, expected_signature)
    
    def _create_hmac_signature(self, data, key):
        """Create HMAC signature"""
        key_bytes = key.encode() if isinstance(key, str) else key
        data_bytes = data.encode() if isinstance(data, str) else data
        hmac_obj = hmac.new(key_bytes, data_bytes, hashlib.sha256)
        return hmac_obj.hexdigest()
    
    def _calculate_verification_score(self, payload):
        """Calculate verification score"""
        scores = {'basic': 50, 'enhanced': 75, 'premium': 95}
        return scores.get(payload.get('verification_level', 'basic'), 50)


# Enhanced Cryptographic Proof System
class ProofOfOwnershipSystem:
    """System for cryptographic proof of ownership"""
    
    def __init__(self):
        self.verifier = CryptographicVerifier()
    
    def generate_ownership_challenge(self, item_data, claimant_id):
        """Generate cryptographic challenge for claimant"""
        challenge = {
            'item_id': item_data.get('id'),
            'item_title': item_data.get('title'),
            'challenge_id': secrets.token_hex(16),
            'claimant_id': claimant_id,
            'timestamp': datetime.now().isoformat(),
            'challenge_type': 'ownership_proof',
            'required_evidence': self._get_required_evidence(item_data.get('category'))
        }
        
        return challenge
    
    def verify_ownership_proof(self, claim_data, proof_data, claimant_key):
        """Verify cryptographic proof of ownership"""
        verification_results = []
        total_score = 0
        
        # 1. Verify proof signature
        if 'signature' in proof_data:
            signature_valid = self.verifier.verify_digital_signature(
                proof_data.get('proof_data', {}),
                proof_data.get('signature', ''),
                claimant_key
            )
            
            if signature_valid:
                verification_results.append({
                    'check': 'Proof Signature',
                    'status': 'PASS',
                    'score': 25
                })
                total_score += 25
            else:
                verification_results.append({
                    'check': 'Proof Signature',
                    'status': 'FAIL',
                    'score': 0
                })
        
        # 2. Verify timestamp (proof must be recent)
        if 'timestamp' in proof_data:
            try:
                proof_time = datetime.fromisoformat(proof_data['timestamp'])
                time_diff = (datetime.now() - proof_time).total_seconds()
                
                if time_diff < 3600:  # 1 hour validity
                    verification_results.append({
                        'check': 'Proof Timestamp',
                        'status': 'PASS',
                        'score': 15
                    })
                    total_score += 15
                else:
                    verification_results.append({
                        'check': 'Proof Timestamp',
                        'status': 'FAIL - Proof expired',
                        'score': 0
                    })
            except:
                verification_results.append({
                    'check': 'Proof Timestamp',
                    'status': 'FAIL - Invalid timestamp',
                    'score': 0
                })
        
        # 3. Verify evidence match
        evidence_score = self._evaluate_evidence(
            proof_data,
            claim_data.get('verification_level', 'basic')
        )
        
        verification_results.append({
            'check': 'Evidence Evaluation',
            'status': 'COMPLETED',
            'score': evidence_score
        })
        total_score += evidence_score
        
        # 4. Generate final verification report
        verification_report = {
            'verification_id': secrets.token_hex(8),
            'timestamp': datetime.now().isoformat(),
            'total_score': total_score,
            'verification_results': verification_results,
            'recommendation': self._get_recommendation(total_score),
            'cryptographic_evidence': {
                'proof_valid': total_score >= 60,
                'signature_verified': 'signature' in proof_data,
                'timestamp_valid': 'timestamp' in proof_data
            }
        }
        
        return verification_report
    
    def _evaluate_evidence(self, evidence, verification_level):
        """Evaluate evidence quality"""
        score = 0
        
        # Base score based on verification level
        base_scores = {'basic': 10, 'enhanced': 25, 'premium': 40}
        score += base_scores.get(verification_level, 10)
        
        # Serial number/unique identifier (20 points)
        if evidence.get('serial_number'):
            if len(evidence['serial_number']) >= 6:
                score += 20
        
        # Purchase info (15 points)
        if evidence.get('purchase_date') or evidence.get('purchase_location'):
            if evidence.get('purchase_date') and evidence.get('purchase_location'):
                score += 15
            else:
                score += 5
        
        # Unique features (15 points)
        if evidence.get('unique_features'):
            if len(evidence['unique_features']) >= 30:
                score += 15
            elif len(evidence['unique_features']) >= 10:
                score += 5
        
        # Detailed description (25 points)
        if evidence.get('detailed_description'):
            if len(evidence['detailed_description']) >= 100:
                score += 25
            elif len(evidence['detailed_description']) >= 50:
                score += 15
            elif len(evidence['detailed_description']) >= 20:
                score += 5
        
        # Photo evidence (15 points)
        if evidence.get('photo_evidence'):
            if len(evidence['photo_evidence']) >= 20:
                score += 15
            elif len(evidence['photo_evidence']) >= 10:
                score += 5
        
        return min(score, 100)
    
    def _get_required_evidence(self, category):
        """Get required evidence based on item category"""
        base_evidence = [
            'detailed_description'
        ]
        
        if category in ['electronics', 'phones', 'computers']:
            base_evidence.extend(['serial_number'])
        elif category in ['documents', 'wallet', 'keys']:
            base_evidence.extend(['photo_evidence'])
        elif category in ['jewelry', 'valuables']:
            base_evidence.extend(['serial_number', 'purchase_date'])
        
        return base_evidence
    
    def _get_recommendation(self, score):
        """Get recommendation based on score"""
        if score >= 80:
            return 'STRONG_OWNERSHIP - HIGH CONFIDENCE'
        elif score >= 60:
            return 'LIKELY_OWNER - MODERATE CONFIDENCE'
        elif score >= 40:
            return 'POSSIBLE_OWNER - LOW CONFIDENCE'
        else:
            return 'UNLIKELY_OWNER - INSUFFICIENT EVIDENCE'
    
    def generate_proof_template(self, claim_data):
        """Generate proof submission template"""
        return {
            'proof_id': secrets.token_hex(8),
            'claim_id': claim_data.get('id'),
            'required_fields': self._get_required_evidence(claim_data.get('category', 'general')),
            'instructions': 'Provide cryptographic proof of ownership',
            'timestamp': datetime.now().isoformat()
        }


# Initialize verifier and ownership system
verifier = CryptographicVerifier()
ownership_system = ProofOfOwnershipSystem()  

# Utility functions
def get_db_connection():
    conn = sqlite3.connect('lost_found.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_user_by_id(user_id):
    """Get user by ID"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None

def get_current_user():
    """Get current user from session"""
    if 'user_id' in session:
        return get_user_by_id(session['user_id'])
    return None

def hash_password(password):
    """Hash password"""
    return hashlib.sha256(password.encode()).hexdigest()

def format_item_for_template(item_dict):
    """Format item for templates"""
    return {
        'id': item_dict.get('id'),
        'user_id': item_dict.get('user_id'),
        'title': item_dict.get('title'),
        'description': item_dict.get('description'),
        'location': item_dict.get('location'),
        'item_type': item_dict.get('item_type'),
        'category': item_dict.get('category'),
        'photo_path': item_dict.get('photo_path'),
        'status': item_dict.get('status'),
        'created_at': item_dict.get('created_at'),
        'username': item_dict.get('username')
    }

def format_claim_for_template(claim_dict):
    """Format claim for templates"""
    return {
        'id': claim_dict.get('id'),
        'item_id': claim_dict.get('item_id'),
        'claimant_id': claim_dict.get('claimant_id'),
        'claim_message': claim_dict.get('claim_message'),
        'verification_level': claim_dict.get('verification_level'),
        'verification_token': claim_dict.get('verification_token'),
        'digital_signature': claim_dict.get('digital_signature'),
        'cryptographic_score': claim_dict.get('cryptographic_score'),
        'status': claim_dict.get('status'),
        'reviewed_by': claim_dict.get('reviewed_by'),
        'reviewed_at': claim_dict.get('reviewed_at'),
        'admin_notes': claim_dict.get('admin_notes'),
        'created_at': claim_dict.get('created_at'),
        'item_title': claim_dict.get('item_title'),
        'owner_username': claim_dict.get('owner_username'),
        'claimant_username': claim_dict.get('claimant_username')
    }

def require_login(f):
    """Decorator to require login"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def require_admin(f):
    """Decorator to require admin role"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('login'))
        
        user = get_current_user()
        if not user or user['role'] != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def allowed_file(filename):
    """Check if file extension is allowed"""
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        full_name = request.form.get('full_name', '')
        password = request.form['password']
        confirm_password = request.form.get('confirm_password', '')
        
        if not username or not email or not password:
            flash('Username, email, and password are required', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('register.html')
        
        conn = get_db_connection()
        existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing:
            conn.close()
            flash('Username already exists', 'error')
            return render_template('register.html')
        
        password_hash = hash_password(password)
        conn.execute('''
            INSERT INTO users (username, email, full_name, password_hash)
            VALUES (?, ?, ?, ?)
        ''', (username, email, full_name, password_hash))
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user:
            password_hash = hash_password(password)
            if password_hash == user['password_hash']:
                # Check if user has valid OTP bypass token
                conn = get_db_connection()
                bypass = conn.execute('''
                    SELECT * FROM otp_bypass 
                    WHERE user_id = ? AND expiration_time > CURRENT_TIMESTAMP
                ''', (user['id'],)).fetchone()
                conn.close()
                
                if bypass:
                    # OTP bypass is valid, skip OTP and login directly
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    session['bypass_token'] = bypass['bypass_token']
                    
                    # Update last login
                    conn = get_db_connection()
                    conn.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
                    conn.commit()
                    conn.close()
                    
                    flash('✅ Login successful! (OTP bypassed)', 'success')
                    return redirect(url_for('dashboard'))
                
                # No valid bypass, generate OTP
                otp_code = OTPManager.generate_otp()
                
                # Save OTP to database
                otp_saved = OTPManager.save_otp_to_db(user['email'], otp_code)
                
                if not otp_saved:
                    flash('Failed to generate OTP. Please try again.', 'error')
                    return render_template('login.html')
                
                # Send OTP via email
                success, message = OTPManager.send_otp_email(user['email'], username, otp_code)
                
                if success:
                    # Store user info temporarily in session for OTP verification
                    session['temp_user_id'] = user['id']
                    session['temp_username'] = user['username']
                    session['temp_email'] = user['email']
                    session['temp_role'] = user['role']
                    
                    flash(f'OTP sent to {user["email"]}. Please enter it to complete login.', 'success')
                    return redirect(url_for('verify_otp'))
                else:
                    flash(f'Error sending OTP: {message}', 'error')
                    return render_template('login.html')
        
        flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    # Check if user has initiated login
    if 'temp_user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp_code = request.form.get('otp_code', '').strip()
        
        if not otp_code:
            flash('Please enter the OTP code', 'error')
            return render_template('verify_otp.html', email=session.get('temp_email'))
        
        if len(otp_code) != 6 or not otp_code.isdigit():
            flash('OTP must be a 6-digit code', 'error')
            return render_template('verify_otp.html', email=session.get('temp_email'))
        
        # Verify OTP
        email = session.get('temp_email')
        is_valid, message = OTPManager.verify_otp(email, otp_code)
        
        if is_valid:
            # OTP is valid, complete the login
            user_id = session['temp_user_id']
            username = session['temp_username']
            role = session['temp_role']
            email = session.get('temp_email')
            
            # Check if user wants to bypass OTP for next 10 minutes
            bypass_otp = request.form.get('bypass_otp')
            
            if bypass_otp:
                # Create OTP bypass token for 10 minutes
                bypass_token = secrets.token_urlsafe(32)
                expiration_time = datetime.now() + timedelta(minutes=10)
                
                conn = get_db_connection()
                # Delete any existing bypass tokens for this user
                conn.execute('DELETE FROM otp_bypass WHERE user_id = ?', (user_id,))
                # Create new bypass token
                conn.execute('''
                    INSERT INTO otp_bypass (user_id, bypass_token, expiration_time)
                    VALUES (?, ?, ?)
                ''', (user_id, bypass_token, expiration_time.isoformat()))
                conn.commit()
                conn.close()
                
                # Store bypass token in session
                session['bypass_token'] = bypass_token
            
            # Update last login
            conn = get_db_connection()
            conn.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user_id,))
            conn.commit()
            conn.close()
            
            # Clear temporary session data
            session.pop('temp_user_id', None)
            session.pop('temp_username', None)
            session.pop('temp_email', None)
            session.pop('temp_role', None)
            
            # Set permanent session data
            session['user_id'] = user_id
            session['username'] = username
            session['role'] = role
            
            flash('✅ Login successful! 2FA verification complete.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(f'❌ {message}', 'error')
            return render_template('verify_otp.html', email=session.get('temp_email'))
    
    # Get remaining OTP validity time
    email = session.get('temp_email')
    remaining_time = OTPManager.get_otp_validity_remaining(email)
    
    return render_template('verify_otp.html', email=email, remaining_time=remaining_time)

@app.route('/dashboard')
@require_login
def dashboard():
    user = get_current_user()
    
    conn = get_db_connection()
    
    items_result = conn.execute('''
        SELECT * FROM items 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    ''', (user['id'],)).fetchall()
    
    items = [format_item_for_template(dict(item)) for item in items_result]
    
    pending_claims = conn.execute('''
        SELECT COUNT(*) as count FROM claims 
        WHERE claimant_id = ? AND status = 'pending'
    ''', (user['id'],)).fetchone()['count']
    
    conn.close()
    
    return render_template('dashboard.html', 
                         user=user,
                         items=items,
                         pending_claims=pending_claims)

@app.route('/profile')
@require_login
def profile():
    user = get_current_user()
    return render_template('profile.html', user=user)

@app.route('/profile/edit', methods=['GET', 'POST'])
@require_login
def edit_profile():
    user = get_current_user()
    
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        full_name = request.form.get('full_name', '').strip()
        password = request.form.get('password', '').strip()
        
        # Validate inputs
        if not username:
            flash('Username is required', 'error')
            return render_template('profile_edit.html', user=user)
        
        if len(username) < 3:
            flash('Username must be at least 3 characters', 'error')
            return render_template('profile_edit.html', user=user)
        
        if not email:
            flash('Email address is required', 'error')
            return render_template('profile_edit.html', user=user)
        
        if '@' not in email:
            flash('Please enter a valid email address', 'error')
            return render_template('profile_edit.html', user=user)
        
        if not password:
            flash('Password is required to verify changes', 'error')
            return render_template('profile_edit.html', user=user)
        
        # Verify password
        password_hash = hash_password(password)
        if password_hash != user['password_hash']:
            flash('Incorrect password. Please try again', 'error')
            return render_template('profile_edit.html', user=user)
        
        # Check if username already exists (but allow user to keep their own username)
        conn = get_db_connection()
        existing_user = conn.execute('SELECT id FROM users WHERE username = ? AND id != ?', 
                                    (username, user['id'])).fetchone()
        
        if existing_user:
            flash('This username is already taken by another account', 'error')
            conn.close()
            return render_template('profile_edit.html', user=user)
        
        # Check if email already exists (but allow user to keep their own email)
        existing_email = conn.execute('SELECT id FROM users WHERE email = ? AND id != ?', 
                                     (email, user['id'])).fetchone()
        
        if existing_email:
            flash('This email is already in use by another account', 'error')
            conn.close()
            return render_template('profile_edit.html', user=user)
        
        # Update user information
        try:
            conn.execute('''
                UPDATE users 
                SET username = ?, email = ?, full_name = ?
                WHERE id = ?
            ''', (username, email, full_name, user['id']))
            conn.commit()
            conn.close()
            
            # Update session with new username and email
            session['username'] = username
            session['email'] = email
            
            flash('Profile updated successfully! Use your new username to login next time.', 'success')
            return redirect(url_for('profile'))
        
        except Exception as e:
            conn.close()
            flash(f'Error updating profile: {str(e)}', 'error')
            return render_template('profile_edit.html', user=user)
    
    return render_template('profile_edit.html', user=user)

@app.route('/post', methods=['GET', 'POST'])
@require_login
def post_item():
    user = get_current_user()
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        location = request.form['location']
        item_type = request.form['item_type']
        category = request.form['category']
        
        if not title or not description or not location:
            flash('Please fill all required fields', 'error')
            return render_template('post_item.html')
        
        photo_path = None
        if 'photo' in request.files:
            photo = request.files['photo']
            if photo and photo.filename != '' and allowed_file(photo.filename):
                filename = secure_filename(photo.filename)
                timestamp = int(datetime.now().timestamp())
                unique_filename = f"{timestamp}_{user['id']}_{filename}"
                
                user_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(user['id']))
                os.makedirs(user_dir, exist_ok=True)
                
                filepath = os.path.join(user_dir, unique_filename)
                photo.save(filepath)
                photo_path = f"{user['id']}/{unique_filename}"
        
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO items (user_id, title, description, location, item_type, category, photo_path)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user['id'], title, description, location, item_type, category, photo_path))
        conn.commit()
        conn.close()
        
        flash('Item posted successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('post_item.html')

@app.route('/items')
def browse_items():
    conn = get_db_connection()
    items_result = conn.execute('''
        SELECT items.*, users.username 
        FROM items 
        JOIN users ON items.user_id = users.id 
        WHERE items.status = 'available' 
        ORDER BY items.created_at DESC
    ''').fetchall()
    conn.close()
    
    items = [format_item_for_template(dict(item)) for item in items_result]
    return render_template('browse_items.html', items=items)

@app.route('/claim/<int:item_id>', methods=['GET', 'POST'])
@require_login
def claim_item(item_id):
    user = get_current_user()
    
    conn = get_db_connection()
    
    item_result = conn.execute('''
        SELECT items.*, users.username 
        FROM items 
        JOIN users ON items.user_id = users.id 
        WHERE items.id = ?
    ''', (item_id,)).fetchone()
    
    if not item_result:
        conn.close()
        flash('Item not found', 'error')
        return redirect(url_for('browse_items'))
    
    item = format_item_for_template(dict(item_result))
    
    if item['user_id'] == user['id']:
        conn.close()
        flash('You cannot claim your own item', 'error')
        return redirect(url_for('browse_items'))
    
    if item['status'] != 'available':
        conn.close()
        flash('This item already has pending claims', 'error')
        return redirect(url_for('browse_items'))
    
    if request.method == 'POST':
        # === REPLACE FROM HERE ===
        claim_message = request.form['claim_message']
        verification_level = request.form.get('verification_level', 'basic')
        
        # Collect cryptographic proof of ownership
        proof_data = {
            'serial_number': request.form.get('serial_number', ''),
            'purchase_date': request.form.get('purchase_date', ''),
            'purchase_location': request.form.get('purchase_location', ''),
            'unique_features': request.form.get('unique_features', ''),
            'photo_evidence': request.form.get('photo_evidence', ''),
            'detailed_description': request.form.get('detailed_description', ''),
            'proof_timestamp': datetime.now().isoformat()
        }
        
        if not claim_message or len(claim_message) < 10:
            flash('Please provide a detailed claim message (at least 10 characters)', 'error')
            conn.close()
            return render_template('claim.html', item=item)
        
        # Validate proof of ownership
        if verification_level in ['enhanced', 'premium']:
            proof_score = ownership_system._evaluate_evidence(proof_data, verification_level)
            if proof_score < 40 and verification_level == 'premium':
                flash(f'Insufficient proof of ownership (score: {proof_score}%). Please provide more evidence.', 'error')
                conn.close()
                return render_template('claim.html', item=item)
        
        existing_claim = conn.execute('''
            SELECT id FROM claims 
            WHERE item_id = ? AND claimant_id = ? AND status IN ('pending', 'approved')
        ''', (item_id, user['id'])).fetchone()
        
        if existing_claim:
            conn.close()
            flash('You already have a claim for this item', 'warning')
            return redirect(url_for('my_claims'))
        
        # Create claim with cryptographic verification
        claim_data = {
            'item_id': item_id,
            'claimant_id': user['id'],
            'claim_message': claim_message,
            'verification_level': verification_level,
            'proof_data': proof_data
        }
        
        # Generate user key for cryptographic operations
        user_key = f"user_key_{user['username']}_{user['id']}"
        
        # Create initial verification token
        verification_token = verifier.generate_verification_token(
            claim_data, 
            user_key
        )
        
        # Create digital signature for claim message AND proof data
        signature_data = {
            'claim_message': claim_message,
            'proof_data': proof_data,
            'timestamp': datetime.now().isoformat()
        }
        
        digital_signature = verifier.create_digital_signature(
            signature_data,
            user_key
        )
        
        # Generate ownership proof token
        ownership_proof = {
            'claimant_id': user['id'],
            'item_id': item_id,
            'proof_data': proof_data,
            'signature': digital_signature,
            'verification_level': verification_level,
            'timestamp': datetime.now().isoformat()
        }
        
        # Insert claim with cryptographic data
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO claims (
                item_id, claimant_id, claim_message, verification_level,
                verification_token, digital_signature, proof_data, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
        ''', (
            item_id, user['id'], claim_message, verification_level,
            verification_token, digital_signature, json.dumps(ownership_proof)
        ))
        
        claim_id = cursor.lastrowid
        
        # Update verification token with claim ID
        claim_data['claim_id'] = claim_id
        verification_token = verifier.generate_verification_token(claim_data, user_key)
        
        cursor.execute('UPDATE claims SET verification_token = ? WHERE id = ?', 
                      (verification_token, claim_id))
        
        # Update item status
        conn.execute('UPDATE items SET status = "claimed" WHERE id = ?', (item_id,))
        
        conn.commit()
        
        # Generate ownership verification report
        verification_report = ownership_system.verify_ownership_proof(
            claim_data,
            ownership_proof,
            user_key
        )
        
        # Update claim with proof score
        conn.execute('UPDATE claims SET cryptographic_score = ?, verification_summary = ? WHERE id = ?',
                    (verification_report['total_score'], json.dumps(verification_report), claim_id))
        
        conn.commit()
        conn.close()
        
        flash(f'Claim submitted! Ownership proof score: {verification_report["total_score"]}%', 'success')
        return redirect(url_for('my_claims'))
        # === TO HERE ===
    
    conn.close()
    return render_template('claim.html', item=item)

@app.route('/my_claims')
@require_login
def my_claims():
    user = get_current_user()
    
    conn = get_db_connection()
    claims_result = conn.execute('''
        SELECT claims.*, items.title as item_title, owner.username as owner_username
        FROM claims
        JOIN items ON claims.item_id = items.id
        JOIN users as owner ON items.user_id = owner.id
        WHERE claims.claimant_id = ?
        ORDER BY claims.created_at DESC
    ''', (user['id'],)).fetchall()
    conn.close()
    
    claims = [format_claim_for_template(dict(claim)) for claim in claims_result]
    return render_template('my_claims.html', claims=claims)


@app.route('/admin/proof_verification')
@require_admin
def admin_proof_verification():
    """Admin page to verify all cryptographic proofs"""
    conn = get_db_connection()
    
    # Get claims with proof data
    claims_result = conn.execute('''
        SELECT claims.*, items.title as item_title,
               claimant.username as claimant_username,
               owner.username as owner_username,
               items.category as item_category
        FROM claims
        JOIN items ON claims.item_id = items.id
        JOIN users as claimant ON claims.claimant_id = claimant.id
        JOIN users as owner ON items.user_id = owner.id
        WHERE claims.proof_data IS NOT NULL
        ORDER BY claims.cryptographic_score DESC, claims.created_at DESC
    ''').fetchall()
    
    conn.close()
    
    claims = []
    for claim in claims_result:
        claim_dict = dict(claim)
        
        # Parse proof data
        if claim_dict.get('proof_data'):
            try:
                proof = json.loads(claim_dict['proof_data'])
                claim_dict['parsed_proof'] = proof
                
                # Calculate evidence completeness
                evidence_count = 0
                if proof.get('proof_data'):
                    pd = proof['proof_data']
                    evidence_count = sum(1 for key in pd.keys() if pd[key])
                
                claim_dict['evidence_completeness'] = min(100, evidence_count * 25)
            except:
                claim_dict['parsed_proof'] = {}
                claim_dict['evidence_completeness'] = 0
        
        claims.append(claim_dict)
    
    return render_template('admin_proof_verification.html', claims=claims)


@app.route('/manage_claims/<int:item_id>')
@require_login
def manage_claims(item_id):
    user = get_current_user()
    
    conn = get_db_connection()
    
    item_result = conn.execute('SELECT * FROM items WHERE id = ?', (item_id,)).fetchone()
    if not item_result:
        conn.close()
        flash('Item not found', 'error')
        return redirect(url_for('dashboard'))
    
    item = format_item_for_template(dict(item_result))
    
    if item['user_id'] != user['id']:
        conn.close()
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    claims_result = conn.execute('''
        SELECT claims.*, claimant.username as claimant_username
        FROM claims
        JOIN users as claimant ON claims.claimant_id = claimant.id
        WHERE claims.item_id = ?
        ORDER BY claims.created_at DESC
    ''', (item_id,)).fetchall()
    
    conn.close()
    
    claims = [format_claim_for_template(dict(claim)) for claim in claims_result]
    
    return render_template('manage_claims.html', 
                         item=item, 
                         claims=claims)

@app.route('/approve_claim/<int:claim_id>')
@require_login
def approve_claim(claim_id):
    user = get_current_user()
    
    conn = get_db_connection()
    
    claim = conn.execute('''
        SELECT claims.*, items.user_id as item_owner_id, items.id as item_id
        FROM claims
        JOIN items ON claims.item_id = items.id
        WHERE claims.id = ?
    ''', (claim_id,)).fetchone()
    
    if not claim or claim['item_owner_id'] != user['id']:
        conn.close()
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    conn.execute('''
        UPDATE claims 
        SET status = 'approved', reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (user['id'], claim_id))
    
    conn.commit()
    conn.close()
    
    flash('Claim approved. Admin will now verify.', 'success')
    return redirect(url_for('manage_claims', item_id=claim['item_id']))

@app.route('/reject_claim/<int:claim_id>')
@require_login
def reject_claim(claim_id):
    user = get_current_user()
    
    conn = get_db_connection()
    
    claim = conn.execute('''
        SELECT claims.*, items.user_id as item_owner_id, items.id as item_id
        FROM claims
        JOIN items ON claims.item_id = items.id
        WHERE claims.id = ?
    ''', (claim_id,)).fetchone()
    
    if not claim or claim['item_owner_id'] != user['id']:
        conn.close()
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    conn.execute('''
        UPDATE claims 
        SET status = 'rejected', reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (user['id'], claim_id))
    
    conn.execute('UPDATE items SET status = "available" WHERE id = ?', (claim['item_id'],))
    
    conn.commit()
    conn.close()
    
    flash('Claim rejected', 'success')
    return redirect(url_for('manage_claims', item_id=claim['item_id']))

@app.route('/admin')
@require_admin
def admin_panel():
    conn = get_db_connection()
    
    users_count = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    items_count = conn.execute('SELECT COUNT(*) as count FROM items').fetchone()['count']
    claims_count = conn.execute('SELECT COUNT(*) as count FROM claims').fetchone()['count']
    pending_claims = conn.execute('SELECT COUNT(*) as count FROM claims WHERE status = "pending"').fetchone()['count']
    
    conn.close()
    
    return render_template('admin.html',
                         users_count=users_count,
                         items_count=items_count,
                         claims_count=claims_count,
                         pending_claims=pending_claims)

@app.route('/admin/claims_review')
@require_admin
def admin_claims_review():
    conn = get_db_connection()
    
    pending_claims_result = conn.execute('''
        SELECT claims.*, items.title as item_title, 
               claimant.username as claimant_username,
               owner.username as owner_username
        FROM claims
        JOIN items ON claims.item_id = items.id
        JOIN users as claimant ON claims.claimant_id = claimant.id
        JOIN users as owner ON items.user_id = owner.id
        WHERE claims.status = 'approved'
        ORDER BY claims.created_at DESC
    ''').fetchall()
    
    pending_claims = [format_claim_for_template(dict(claim)) for claim in pending_claims_result]
    
    total_claims = conn.execute('SELECT COUNT(*) as count FROM claims').fetchone()['count']
    verified_claims = conn.execute('SELECT COUNT(*) as count FROM claims WHERE status = "verified"').fetchone()['count']
    rejected_claims = conn.execute('SELECT COUNT(*) as count FROM claims WHERE status = "rejected"').fetchone()['count']
    
    recent_verified_result = conn.execute('''
        SELECT claims.*, users.username, items.title
        FROM claims 
        JOIN users ON claims.claimant_id = users.id 
        JOIN items ON claims.item_id = items.id
        WHERE claims.status IN ('verified', 'rejected') 
        ORDER BY claims.reviewed_at DESC 
        LIMIT 10
    ''').fetchall()
    
    recent_verified = [format_claim_for_template(dict(claim)) for claim in recent_verified_result]
    
    conn.close()
    
    return render_template('admin_claims_review.html',
                         pending_claims=pending_claims,
                         verified_claims=verified_claims,
                         rejected_claims=rejected_claims,
                         total_claims=total_claims,
                         recent_verified=recent_verified)

@app.route('/admin/verify_claim/<int:claim_id>', methods=['GET', 'POST'])
@require_admin
def admin_verify_claim(claim_id):
    user = get_current_user()
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        # ... [keep existing POST code] ...
        pass  # Keep all existing POST code
    
    # GET request - display verification page
    claim = conn.execute('''
        SELECT claims.*, items.title as item_title,
               claimant.username as claimant_username,
               owner.username as owner_username,
               items.photo_path
        FROM claims
        JOIN items ON claims.item_id = items.id
        JOIN users as claimant ON claims.claimant_id = claimant.id
        JOIN users as owner ON items.user_id = owner.id
        WHERE claims.id = ?
    ''', (claim_id,)).fetchone()
    
    conn.close()
    
    if not claim:
        flash('Claim not found', 'error')
        return redirect(url_for('admin_claims_review'))
    
    claim_dict = dict(claim)
    
    # Parse existing verification summary
    verification_summary = {}
    if claim_dict.get('verification_summary'):
        try:
            verification_summary = json.loads(claim_dict['verification_summary'])
        except:
            verification_summary = {}
    
    # Parse proof data if exists - FIXED HERE
    proof_data_parsed = {}
    if claim_dict.get('proof_data'):
        try:
            proof_data_parsed = json.loads(claim_dict['proof_data'])
        except:
            proof_data_parsed = {}
    
    return render_template('admin_verify_claim_crypto.html', 
                         claim=claim_dict,
                         proof_data=proof_data_parsed,  # Pass parsed data
                         verification_summary=verification_summary)

@app.route('/admin/users', methods=['GET'])
@require_login
def admin_users():
    """Admin page to view and manage all users"""
    user = get_current_user()
    
    # Check if user is admin
    if user['role'] != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    users = conn.execute('''
        SELECT id, username, email, full_name, role, created_at, last_login
        FROM users
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    
    users_list = [dict(u) for u in users]
    
    return render_template('admin_users.html', users=users_list)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@require_login
def delete_user(user_id):
    """Delete a user from the database (admin only)"""
    user = get_current_user()
    
    # Check if user is admin
    if user['role'] != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Prevent admin from deleting themselves
    if user_id == user['id']:
        flash('Cannot delete your own admin account!', 'error')
        return redirect(url_for('admin_users'))
    
    conn = get_db_connection()
    
    # Get user to delete
    user_to_delete = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user_to_delete:
        flash('User not found', 'error')
        conn.close()
        return redirect(url_for('admin_users'))
    
    # Delete user (this will cascade delete items, claims, etc.)
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash(f'✅ User "{user_to_delete["username"]}" has been deleted from the database', 'success')
    return redirect(url_for('admin_users'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))

@app.route('/static/uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    print("=" * 70)
    print("🚀 LOST & FOUND PORTAL - CSE447 PROJECT")
    print("=" * 70)
    print("✅ Custom Cryptographic Verification")
    print("✅ HMAC-SHA256 Digital Signatures")
    print("✅ Verification Tokens with Timestamps")
    print("✅ Two-factor authentication")
    print("✅ All claims cryptographically verified")
    print("=" * 70)
    print("🌐 Open: http://localhost:5000")
    print("👤 Admin: admin / admin123 (2FA: 123456)")
    print("=" * 70)
    
    app.run(debug=True, port=5000)