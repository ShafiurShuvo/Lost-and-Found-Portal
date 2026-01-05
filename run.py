# run.py
import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app

if __name__ == '__main__':
    print("=" * 70)
    print("🔐 LOST & FOUND PORTAL WITH CUSTOM ENCRYPTION")
    print("=" * 70)
    print("✅ Custom RSA implementation (from scratch)")
    print("✅ Custom ECC implementation (from scratch)")
    print("✅ Multi-level encryption (RSA + ECC)")
    print("✅ HMAC data integrity")
    print("✅ Two-factor authentication")
    print("✅ All data encrypted before storage")
    print("=" * 70)
    print("🌐 Open: http://localhost:5000")
    print("👤 Admin: admin / admin123 (2FA: 123456)")
    print("=" * 70)
    
    # Create necessary directories
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/uploads', exist_ok=True)
    os.makedirs('crypto', exist_ok=True)
    
    app.run(debug=True, port=5000)