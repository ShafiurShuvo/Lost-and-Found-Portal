# migrate_crypto.py
import sqlite3
import os

def migrate_database():
    print("🔄 Migrating database for cryptographic verification...")
    
    conn = sqlite3.connect('lost_found.db')
    c = conn.cursor()
    
    # Check if columns already exist
    c.execute("PRAGMA table_info(claims)")
    columns = [col[1] for col in c.fetchall()]
    
    # Add new columns if they don't exist
    new_columns = [
        ('verification_token', 'TEXT'),
        ('digital_signature', 'TEXT'),
        ('verification_summary', 'TEXT'),
        ('cryptographic_score', 'INTEGER DEFAULT 0')
    ]
    
    for col_name, col_type in new_columns:
        if col_name not in columns:
            try:
                c.execute(f"ALTER TABLE claims ADD COLUMN {col_name} {col_type}")
                print(f"✅ Added column: {col_name}")
            except Exception as e:
                print(f"⚠️  Could not add {col_name}: {e}")
    
    conn.commit()
    conn.close()
    print("🎉 Migration completed!")

if __name__ == '__main__':
    migrate_database()