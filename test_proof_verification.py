# test_proof_verification.py
import sqlite3
import json
from datetime import datetime

def test_proof_verification():
    print("🔍 TESTING PROOF OF OWNERSHIP VERIFICATION")
    print("="*60)
    
    conn = sqlite3.connect('lost_found.db')
    conn.row_factory = sqlite3.Row
    
    # Get a claim with proof data
    c = conn.cursor()
    c.execute('''
        SELECT claims.*, items.title, users.username 
        FROM claims 
        JOIN items ON claims.item_id = items.id 
        JOIN users ON claims.claimant_id = users.id 
        WHERE claims.proof_data IS NOT NULL 
        LIMIT 1
    ''')
    
    claim = c.fetchone()
    
    if not claim:
        print("❌ No claims with proof data found.")
        print("Please submit a claim with 'premium' verification level first.")
        return
    
    claim_dict = dict(claim)
    print(f"📋 Claim ID: {claim_dict['id']}")
    print(f"📦 Item: {claim_dict['title']}")
    print(f"👤 Claimant: {claim_dict['username']}")
    print(f"🎯 Verification Level: {claim_dict['verification_level']}")
    print(f"📊 Cryptographic Score: {claim_dict['cryptographic_score']}%")
    print("")
    
    # Parse proof data
    try:
        proof = json.loads(claim_dict['proof_data'])
        print("🔐 CRYPTOGRAPHIC PROOF ANALYSIS:")
        print("-"*60)
        
        # Check signature
        if proof.get('signature'):
            sig = proof['signature']
            print(f"✓ Digital Signature: {sig[:30]}...")
            print(f"  Signature Length: {len(sig)} characters (expected: 64)")
        else:
            print("✗ No digital signature found")
        
        # Check timestamp
        if proof.get('timestamp'):
            proof_time = datetime.fromisoformat(proof['timestamp'].replace('Z', '+00:00'))
            time_diff = (datetime.now() - proof_time).total_seconds()
            print(f"✓ Timestamp: {proof_time}")
            print(f"  Age: {time_diff:.0f} seconds ({'VALID' if time_diff < 3600 else 'EXPIRED'})")
        
        # Check proof data
        if proof.get('proof_data'):
            pd = proof['proof_data']
            print(f"📝 EVIDENCE PROVIDED:")
            evidence_count = 0
            
            for key, value in pd.items():
                if value:
                    evidence_count += 1
                    if key == 'detailed_description':
                        print(f"  • {key}: {len(value)} characters")
                    else:
                        print(f"  • {key}: {value[:50]}{'...' if len(str(value)) > 50 else ''}")
            
            print(f"\n📊 EVIDENCE SUMMARY:")
            print(f"  Total evidence pieces: {evidence_count}")
            print(f"  Expected score: {claim_dict['cryptographic_score']}%")
            
            if claim_dict['cryptographic_score'] >= 80:
                print("  ✅ STRONG PROOF - High confidence of ownership")
            elif claim_dict['cryptographic_score'] >= 60:
                print("  ⚠️  MODERATE PROOF - Likely owner")
            elif claim_dict['cryptographic_score'] >= 40:
                print("  ⚠️  WEAK PROOF - Requires additional verification")
            else:
                print("  ❌ INSUFFICIENT PROOF - Unlikely owner")
        
        print("\n" + "="*60)
        print("🎯 VERIFICATION RECOMMENDATION:")
        
        if claim_dict['cryptographic_score'] >= 70:
            print("✅ APPROVE - Strong cryptographic proof provided")
        elif claim_dict['cryptographic_score'] >= 50:
            print("⚠️  REVIEW - Requires manual verification")
        else:
            print("❌ REJECT - Insufficient cryptographic evidence")
            
    except Exception as e:
        print(f"❌ Error parsing proof data: {e}")
    
    conn.close()

if __name__ == '__main__':
    test_proof_verification()