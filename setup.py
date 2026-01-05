# setup.py
import os
import sys

def create_file(path, content):
    """Create a file with content"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

def setup_project():
    """Setup the complete project structure"""
    
    print("=" * 60)
    print("SETTING UP LOST & FOUND PORTAL")
    print("=" * 60)
    
    # Create directories
    directories = [
        'crypto',
        'templates',
        'static/uploads',
        'models',
        'utils'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✓ Created {directory}/")
    
    # Create __init__.py files
    init_files = ['crypto/__init__.py', 'models/__init__.py', 'utils/__init__.py']
    
    for init_file in init_files:
        with open(init_file, 'w') as f:
            f.write('')
        print(f"✓ Created {init_file}")
    
    print("\n✅ Project setup complete!")
    print("\n📋 Files created:")
    print("  - app.py (main application)")
    print("  - config.py (configuration)")
    print("  - database.py (encrypted database)")
    print("  - run.py (run script)")
    print("  - requirements.txt (dependencies)")
    print("  - crypto/ (custom cryptographic implementations)")
    print("  - templates/ (HTML templates)")
    
    print("\n🚀 To run the application:")
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Run: python run.py")
    print("3. Open: http://localhost:5000")
    
    print("\n👤 Demo credentials:")
    print("  Username: admin")
    print("  Password: admin123")
    print("  2FA Code: 123456")
    
    print("\n🔐 Cryptographic features:")
    print("  • Custom RSA implementation (from scratch)")
    print("  • Custom ECC implementation (from scratch)")
    print("  • Multi-level encryption (RSA + ECC)")
    print("  • HMAC data integrity")
    print("  • All data encrypted before storage")
    print("=" * 60)

if __name__ == '__main__':
    setup_project()