# utils/file_handler.py - SIMPLIFIED VERSION
"""
Simple file handler without external dependencies
"""

import os
from werkzeug.utils import secure_filename
from config import Config

class FileHandler:
    """Handle file uploads"""
    
    @staticmethod
    def allowed_file(filename):
        """Check if file extension is allowed"""
        if not filename or '.' not in filename:
            return False
        extension = filename.rsplit('.', 1)[1].lower()
        return extension in Config.ALLOWED_EXTENSIONS
    
    @staticmethod
    def save_uploaded_file(file, user_id):
        """Save uploaded file"""
        if file and file.filename != '':
            if not FileHandler.allowed_file(file.filename):
                return None, "File type not allowed"
            
            # Secure the filename
            filename = secure_filename(file.filename)
            
            # Create unique filename
            import time
            timestamp = int(time.time())
            unique_filename = f"{timestamp}_{user_id}_{filename}"
            
            # Create user directory
            user_dir = os.path.join(Config.UPLOAD_FOLDER, str(user_id))
            os.makedirs(user_dir, exist_ok=True)
            
            # Save file
            filepath = os.path.join(user_dir, unique_filename)
            file.save(filepath)
            
            if os.path.exists(filepath):
                return f"{user_id}/{unique_filename}", None
        
        return None, "No file provided"