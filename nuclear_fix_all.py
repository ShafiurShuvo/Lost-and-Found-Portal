# nuclear_fix_all.py - Removes ALL .decrypted_data. references
import os

templates = [
    'dashboard.html',
    'browse_items.html',
    'claim.html',
    'manage_claims.html',
    'my_claims.html',
    'admin_claims_review.html',
    'admin_verify_claim.html',
    'admin_verify_claim_crypto.html'
]

for template in templates:
    filepath = os.path.join('templates', template)
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Remove ALL .decrypted_data. references
        content = content.replace('.decrypted_data.', '.')
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"☢️  Fixed: {template}")
    else:
        print(f"⚠️  Not found: {template}")

print("\n✅ ALL .decrypted_data. references removed!")