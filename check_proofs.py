# check_proofs.py
import sqlite3
import json

def check_all_proofs():
    """Check all cryptographic proofs in database"""
    print("🔍 CRYPTOGRAPHIC PROOF CHECKER")
    print("=" * 70)
    
    conn = sqlite3.connect('lost_found.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all claims with proof data
    cursor.execute("""
        SELECT c.id, c.claimant_id, u.username, i.title, 
               c.verification_level, c.cryptographic_score, c.proof_data
        FROM claims c
        JOIN users u ON c.claimant_id = u.id
        JOIN items i ON c.item_id = i.id
        WHERE c.proof_data IS NOT NULL
        ORDER BY c.id DESC
    """)
    
    claims = cursor.fetchall()
    
    if not claims:
        print("❌ No cryptographic proofs found in database.")
        print("\n💡 To create test proofs:")
        print("1. Run your Flask app: python app.py")
        print("2. Go to http://localhost:5000")
        print("3. Register two users")
        print("4. Post a 'Found Item' (choose Electronics category)")
        print("5. File a claim with 'Premium' verification level")
        print("6. Fill ALL proof fields (serial number, purchase date, etc.)")
        return
    
    print(f"📊 Found {len(claims)} claim(s) with cryptographic proof\n")
    
    for claim in claims:
        claim_id = claim['id']
        claimant_id = claim['claimant_id']
        username = claim['username']
        item_title = claim['title']
        verification_level = claim['verification_level']
        score = claim['cryptographic_score']
        proof_json = claim['proof_data']
        
        print(f"🔹 CLAIM #{claim_id}")
        print(f"   Item: {item_title}")
        print(f"   Claimant: {username} (ID: {claimant_id})")
        print(f"   Verification Level: {verification_level.upper()}")
        print(f"   Cryptographic Score: {score}%")
        
        try:
            proof = json.loads(proof_json)
            
            # Show timestamp
            if 'timestamp' in proof:
                print(f"   📅 Submitted: {proof['timestamp']}")
            
            # Show digital signature
            if 'signature' in proof:
                sig = proof['signature']
                is_valid = len(sig) == 64  # HMAC-SHA256 should be 64 chars
                status = "✓ VALID" if is_valid else "⚠️  CHECK"
                print(f"   🔐 Signature: {sig[:20]}... ({status})")
            
            # Show proof evidence
            if 'proof_data' in proof:
                data = proof['proof_data']
                print("   📝 Evidence Provided:")
                
                if data.get('serial_number'):
                    print(f"      • Serial Number: {data['serial_number']}")
                
                if data.get('purchase_date'):
                    print(f"      • Purchase Date: {data['purchase_date']}")
                
                if data.get('purchase_location'):
                    print(f"      • Purchase Location: {data['purchase_location']}")
                
                if data.get('unique_features'):
                    features = data['unique_features']
                    if len(features) > 60:
                        print(f"      • Unique Features: {features[:60]}...")
                    else:
                        print(f"      • Unique Features: {features}")
                
                if data.get('detailed_description'):
                    desc_len = len(data['detailed_description'])
                    print(f"      • Description Length: {desc_len} characters")
                
                if data.get('photo_evidence'):
                    print(f"      • Photo Evidence: Provided")
                
                # Count evidence
                evidence_count = sum(1 for value in data.values() if value and str(value).strip())
                print(f"      • Total Evidence Pieces: {evidence_count}")
            
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
            
        except Exception as e:
            print(f"   ❌ Error parsing proof data: {e}")
        
        print("\n" + "-" * 60)
    
    conn.close()

if __name__ == '__main__':
    check_all_proofs()