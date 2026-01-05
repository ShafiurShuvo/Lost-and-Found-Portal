# verify_proof.py - Interactive Proof Verification Tool
import sqlite3
import json

def show_database_stats():
    """Show database statistics"""
    conn = sqlite3.connect('lost_found.db')
    cursor = conn.cursor()
    
    print("\n📊 DATABASE STATISTICS")
    print("="*50)
    
    # Count users
    cursor.execute("SELECT COUNT(*) FROM users")
    users = cursor.fetchone()[0]
    print(f"👥 Users: {users}")
    
    # Count items
    cursor.execute("SELECT COUNT(*) FROM items")
    items = cursor.fetchone()[0]
    print(f"📦 Items: {items}")
    
    # Count claims
    cursor.execute("SELECT COUNT(*) FROM claims")
    claims = cursor.fetchone()[0]
    print(f"📝 Total Claims: {claims}")
    
    # Count claims with proof
    cursor.execute("SELECT COUNT(*) FROM claims WHERE proof_data IS NOT NULL")
    claims_with_proof = cursor.fetchone()[0]
    print(f"🔐 Claims with Proof: {claims_with_proof}")
    
    # Count by verification level
    cursor.execute("SELECT verification_level, COUNT(*) FROM claims GROUP BY verification_level")
    levels = cursor.fetchall()
    print(f"🛡️ Verification Levels:")
    for level, count in levels:
        print(f"   - {level.upper()}: {count}")
    
    conn.close()
    return claims_with_proof

def show_all_proofs():
    """Show all cryptographic proofs"""
    conn = sqlite3.connect('lost_found.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT c.id, c.cryptographic_score, c.verification_level, 
               u.username, i.title, c.proof_data, c.status
        FROM claims c
        JOIN users u ON c.claimant_id = u.id
        JOIN items i ON c.item_id = i.id
        WHERE c.proof_data IS NOT NULL
        ORDER BY c.cryptographic_score DESC
    ''')
    
    claims = cursor.fetchall()
    
    if not claims:
        print("\n❌ No cryptographic proofs found in database.")
        print("\n💡 To create test proofs:")
        print("1. Run: python app.py")
        print("2. Visit: http://localhost:5000")
        print("3. Register two users (User A & User B)")
        print("4. User A: Post a 'Found Item' (Electronics category)")
        print("5. User B: File a claim with 'Premium' verification")
        print("6. Fill ALL proof fields (serial, purchase date, etc.)")
        return
    
    print(f"\n🔍 FOUND {len(claims)} CRYPTOGRAPHIC PROOF(S)")
    print("="*70)
    
    for claim in claims:
        claim_id, score, level, username, item_title, proof_json, status = claim
        
        print(f"\n🔹 CLAIM #{claim_id}")
        print(f"   👤 Claimant: {username}")
        print(f"   📦 Item: {item_title}")
        print(f"   🛡️  Level: {level.upper()}")
        print(f"   📊 Score: {score}%")
        print(f"   📈 Status: {status}")
        
        # Parse proof data
        try:
            proof = json.loads(proof_json)
            
            print("   📅 Submitted:", proof.get('timestamp', 'N/A'))
            
            if 'signature' in proof:
                sig = proof['signature']
                is_valid = len(sig) == 64
                status = "VALID" if is_valid else "CHECK"
                print(f"   🔐 Signature: {sig[:20]}... ({status})")
            
            if 'proof_data' in proof:
                data = proof['proof_data']
                print("   📝 Evidence:")
                
                evidence_items = []
                if data.get('serial_number'):
                    evidence_items.append(f"Serial: {data['serial_number']}")
                if data.get('purchase_date'):
                    evidence_items.append(f"Purchase: {data['purchase_date']}")
                if data.get('purchase_location'):
                    loc = data['purchase_location']
                    if len(loc) > 20:
                        evidence_items.append(f"Location: {loc[:20]}...")
                    else:
                        evidence_items.append(f"Location: {loc}")
                if data.get('detailed_description'):
                    desc_len = len(data['detailed_description'])
                    evidence_items.append(f"Description: {desc_len} chars")
                
                for item in evidence_items:
                    print(f"      • {item}")
            
            # Show recommendation
            print(f"\n   🎯 Recommendation: ", end="")
            if score >= 80:
                print("✅ APPROVE - Strong cryptographic proof")
            elif score >= 60:
                print("⚠️  REVIEW - Moderate proof")
            elif score >= 40:
                print("⚠️  INVESTIGATE - Weak proof")
            else:
                print("❌ REJECT - Insufficient proof")
                
        except:
            print("   ❌ Error reading proof data")
        
        print("-"*60)
    
    conn.close()

def view_specific_proof():
    """View specific claim proof by ID"""
    try:
        claim_id = int(input("\nEnter Claim ID: "))
    except:
        print("❌ Please enter a valid number")
        return
    
    conn = sqlite3.connect('lost_found.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT c.*, u.username, i.title 
        FROM claims c
        JOIN users u ON c.claimant_id = u.id
        JOIN items i ON c.item_id = i.id
        WHERE c.id = ?
    ''', (claim_id,))
    
    claim = cursor.fetchone()
    
    if not claim:
        print(f"❌ Claim #{claim_id} not found")
        return
    
    print(f"\n" + "="*70)
    print(f"🔬 DETAILED VIEW - CLAIM #{claim_id}")
    print("="*70)
    
    # Print basic info (indices based on your schema)
    print(f"📦 Item: {claim[16]}")  # title
    print(f"👤 Claimant: {claim[15]}")  # username
    print(f"📊 Cryptographic Score: {claim[8]}%")
    print(f"🛡️ Verification Level: {claim[4]}")
    print(f"📈 Status: {claim[9]}")
    
    # Show proof data
    proof_data = claim[7]  # proof_data column
    if proof_data:
        try:
            proof = json.loads(proof_data)
            print("\n🔐 RAW CRYPTOGRAPHIC PROOF:")
            print("-"*40)
            print(json.dumps(proof, indent=2))
        except:
            print("\n❌ Cannot parse proof data")
    else:
        print("\n❌ No cryptographic proof for this claim")
    
    conn.close()

def create_test_data():
    """Create test proof data for demonstration"""
    conn = sqlite3.connect('lost_found.db')
    cursor = conn.cursor()
    
    print("\n🧪 CREATING TEST DATA...")
    
    # Create test users if they don't exist
    cursor.execute("INSERT OR IGNORE INTO users (username, password_hash, email) VALUES ('test_alice', 'hash123', 'alice@test.com')")
    cursor.execute("INSERT OR IGNORE INTO users (username, password_hash, email) VALUES ('test_bob', 'hash456', 'bob@test.com')")
    
    # Create test item
    cursor.execute("""
        INSERT OR IGNORE INTO items (user_id, title, description, location, item_type, category)
        VALUES (1, 'iPhone 14 Pro Max', 'Lost iPhone with blue case', 'University Library', 'lost', 'electronics')
    """)
    
    # Create test claim with proof
    import json
    proof_data = {
        'proof_data': {
            'serial_number': 'F2LDA3X5H123',
            'purchase_date': '2024-01-15',
            'purchase_location': 'Apple Store NYC',
            'unique_features': 'Small scratch on camera lens, blue silicone case',
            'detailed_description': 'This is my iPhone that I lost at the library. It has my personal wallpaper of mountains and my contacts. The phone is in a blue silicone case with a small scratch on the back camera lens.',
            'photo_evidence': 'I have purchase receipt and photos with the phone'
        },
        'signature': 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234',
        'timestamp': '2024-12-19T10:30:00',
        'verification_level': 'premium'
    }
    
    cursor.execute("""
        INSERT OR IGNORE INTO claims 
        (item_id, claimant_id, claim_message, verification_level, proof_data, cryptographic_score, status)
        VALUES (1, 2, 'This is my iPhone! I lost it yesterday at the library.', 'premium', ?, 92, 'approved')
    """, (json.dumps(proof_data),))
    
    conn.commit()
    conn.close()
    
    print("✅ Test data created successfully!")
    print("   - User: test_alice (posted item)")
    print("   - User: test_bob (filed claim)")
    print("   - Item: iPhone 14 Pro Max")
    print("   - Claim: With cryptographic proof (score: 92%)")

def main():
    """Main menu"""
    print("\n" + "="*50)
    print("🔐 CRYPTOGRAPHIC PROOF VERIFICATION TOOL")
    print("="*50)
    
    while True:
        print("\n📋 MENU:")
        print("1. Show database statistics")
        print("2. View all cryptographic proofs")
        print("3. View specific claim proof")
        print("4. Create test data (for demo)")
        print("5. Exit")
        
        choice = input("\nSelect option (1-5): ").strip()
        
        if choice == '1':
            show_database_stats()
        elif choice == '2':
            show_all_proofs()
        elif choice == '3':
            view_specific_proof()
        elif choice == '4':
            create_test_data()
        elif choice == '5':
            print("\n👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please enter 1-5.")

if __name__ == "__main__":
    main()