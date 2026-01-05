# quick_check.py - Quick proof checker
import sqlite3
import json

conn = sqlite3.connect('lost_found.db')
cursor = conn.cursor()

# Quick check
cursor.execute("SELECT COUNT(*) FROM claims WHERE proof_data IS NOT NULL")
count = cursor.fetchone()[0]

if count == 0:
    print("❌ No proof data found.")
    print("\nQuick fix: Run this in terminal:")
    print("python verify_proof.py")
    print("Then select option 4 (Create test data)")
else:
    print(f"✅ Found {count} claim(s) with cryptographic proof")
    
    # Show first proof
    cursor.execute("SELECT proof_data FROM claims WHERE proof_data IS NOT NULL LIMIT 1")
    result = cursor.fetchone()
    
    if result:
        try:
            proof = json.loads(result[0])
            print("\n📋 Sample Proof Structure:")
            print(f"   • Has timestamp: {'timestamp' in proof}")
            print(f"   • Has signature: {'signature' in proof}")
            print(f"   • Has proof_data: {'proof_data' in proof}")
            
            if 'proof_data' in proof:
                data = proof['proof_data']
                print(f"   • Evidence fields: {len(data)}")
                for key in data.keys():
                    if data[key]:
                        print(f"     - {key}: {str(data[key])[:40]}...")
        except:
            print("   • Error parsing proof")

conn.close()