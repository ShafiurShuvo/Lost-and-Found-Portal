# migrate_proof_system.py
import sqlite3
import json

def migrate_proof_system():
    print("🔄 Migrating database for proof of ownership system...")
    
    conn = sqlite3.connect('lost_found.db')
    c = conn.cursor()
    
    # Check if proof_data column exists
    c.execute("PRAGMA table_info(claims)")
    columns = [col[1] for col in c.fetchall()]
    
    # Add proof_data column if it doesn't exist
    if 'proof_data' not in columns:
        c.execute("ALTER TABLE claims ADD COLUMN proof_data TEXT")
        print("✅ Added proof_data column")
    
    # Update existing claims with empty proof_data
    c.execute("UPDATE claims SET proof_data = ? WHERE proof_data IS NULL", (json.dumps({}),))
    print("✅ Updated existing claims")
    
    conn.commit()
    conn.close()
    print("🎉 Migration completed!")

if __name__ == '__main__':
    migrate_proof_system()