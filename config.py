# config.py
import os
from datetime import timedelta

class Config:
    # Flask Configuration
    SECRET_KEY = 'secure-secret-key-change-in-production-2024'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    
    # Database Configuration
    DATABASE_NAME = 'lost_found_secure.db'
    
    # Upload Configuration
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB
    
    # App Configuration
    SITE_NAME = 'Lost & Found Portal'
    ADMIN_USERNAME = 'admin'
    ADMIN_PASSWORD = 'admin123'
    
    # Security Configuration
    PASSWORD_HASH_ALGORITHM = 'sha256'
    
    # Two-Factor Authentication
    TOTP_SECRET = 'DEMO2FASECRET123456'
    TOTP_CODE = '123456'  # Demo code for testing

def init_upload_folders():
    """Initialize upload folder structure"""
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    
    # Create .gitkeep to preserve folder in git
    gitkeep_path = os.path.join(Config.UPLOAD_FOLDER, '.gitkeep')
    if not os.path.exists(gitkeep_path):
        with open(gitkeep_path, 'w') as f:
            f.write('# This file keeps the uploads folder in git\n')
    
    print(f"Upload folder initialized at: {Config.UPLOAD_FOLDER}")