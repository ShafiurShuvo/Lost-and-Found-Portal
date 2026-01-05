# fix_templates_final.py
import os
import re

def fix_all_templates():
    templates_dir = 'templates'
    
    # Patterns to fix
    patterns = [
        (r'item\.decrypted_data\.(\w+)', r'item.\1'),
        (r'claim\.decrypted_data\.(\w+)', r'claim.\1'),
        (r'user\.decrypted_data\.(\w+)', r'user.\1'),
    ]
    
    for filename in os.listdir(templates_dir):
        if filename.endswith('.html'):
            filepath = os.path.join(templates_dir, filename)
            
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if file has decrypted_data references
            if 'decrypted_data' in content:
                print(f"🔧 Fixing: {filename}")
                
                # Apply all pattern replacements
                for pattern, replacement in patterns:
                    content = re.sub(pattern, replacement, content)
                
                # Write fixed content
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                print(f"✅ Fixed: {filename}")
            else:
                print(f"✓ Clean: {filename}")
    
    print("\n🎉 All templates have been fixed!")

if __name__ == '__main__':
    fix_all_templates()