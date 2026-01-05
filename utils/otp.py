# utils/otp.py
"""
OTP (One-Time Password) utilities for 2FA via email
"""

import random
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import sqlite3
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class OTPManager:
    """Manage OTP generation, validation, and email sending"""
    
    # Email configuration - using environment variables
    SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    SENDER_EMAIL = os.getenv('SENDER_EMAIL', 'your-email@gmail.com')
    SENDER_PASSWORD = os.getenv('SENDER_PASSWORD', 'your-app-password')
    
    # OTP Configuration
    OTP_LENGTH = int(os.getenv('OTP_LENGTH', 6))
    OTP_VALIDITY_SECONDS = int(os.getenv('OTP_VALIDITY_SECONDS', 300))
    
    @staticmethod
    def generate_otp():
        """Generate a random 6-digit OTP"""
        return ''.join([str(random.randint(0, 9)) for _ in range(OTPManager.OTP_LENGTH)])
    
    @staticmethod
    def save_otp_to_db(email, otp, db_path='lost_found.db'):
        """Save OTP to database with expiration time"""
        try:
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            
            # Calculate expiration time
            expiration_time = datetime.now() + timedelta(seconds=OTPManager.OTP_VALIDITY_SECONDS)
            
            # Delete any existing OTP for this email
            c.execute('DELETE FROM otp_codes WHERE email = ?', (email,))
            
            # Insert new OTP
            c.execute('''
                INSERT INTO otp_codes (email, otp_code, expiration_time, created_at)
                VALUES (?, ?, ?, ?)
            ''', (email, otp, expiration_time.isoformat(), datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"❌ Error saving OTP to database: {str(e)}")
            return False
    
    @staticmethod
    def verify_otp(email, otp_code, db_path='lost_found.db'):
        """Verify if the provided OTP is correct and not expired"""
        try:
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            
            # Get OTP record
            result = c.execute('''
                SELECT otp_code, expiration_time FROM otp_codes 
                WHERE email = ? AND otp_code = ?
            ''', (email, otp_code)).fetchone()
            
            if not result:
                conn.close()
                return False, "Invalid OTP code"
            
            otp_in_db, expiration_time_str = result
            expiration_time = datetime.fromisoformat(expiration_time_str)
            
            # Check if OTP has expired
            if datetime.now() > expiration_time:
                # Delete expired OTP
                c.execute('DELETE FROM otp_codes WHERE email = ?', (email,))
                conn.commit()
                conn.close()
                return False, "OTP has expired. Please login again."
            
            # Delete the OTP after successful verification
            c.execute('DELETE FROM otp_codes WHERE email = ?', (email,))
            conn.commit()
            conn.close()
            
            return True, "OTP verified successfully"
        
        except Exception as e:
            print(f"❌ Error verifying OTP: {str(e)}")
            return False, f"Error verifying OTP: {str(e)}"
    
    @staticmethod
    def send_otp_email(recipient_email, username, otp_code):
        """Send OTP via email"""
        try:
            # Email content
            subject = "Your Lost & Found Portal - 2FA Code"
            
            # HTML email template
            html_content = f"""
            <html>
                <body style="font-family: Arial, sans-serif; background-color: #f5f5f5; padding: 20px;">
                    <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 10px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                        
                        <div style="text-align: center; margin-bottom: 30px;">
                            <h2 style="color: #2c3e50; margin: 0;">🔐 Two-Factor Authentication</h2>
                            <p style="color: #666; margin: 10px 0 0 0;">Lost & Found Portal</p>
                        </div>
                        
                        <div style="background-color: #f0f7ff; border-left: 4px solid #3498db; padding: 20px; border-radius: 5px; margin-bottom: 30px;">
                            <p style="color: #333; margin: 0 0 15px 0;">Hello <strong>{username}</strong>,</p>
                            <p style="color: #555; margin: 0 0 15px 0;">Your One-Time Password (OTP) for secure login is:</p>
                            
                            <div style="background-color: #fff; border: 2px solid #3498db; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
                                <h1 style="color: #3498db; letter-spacing: 5px; margin: 0; font-size: 2.5rem; font-family: 'Courier New', monospace;">
                                    {otp_code}
                                </h1>
                            </div>
                            
                            <p style="color: #e74c3c; font-weight: bold; margin: 15px 0;">⏰ This code is valid for {OTPManager.OTP_VALIDITY_SECONDS // 60} minutes only!</p>
                            <p style="color: #666; margin: 15px 0;">Do not share this code with anyone. We will never ask for this code via email.</p>
                        </div>
                        
                        <div style="background-color: #fff3cd; border-left: 4px solid #f39c12; padding: 20px; border-radius: 5px; margin-bottom: 30px;">
                            <p style="color: #333; margin: 0; font-size: 0.9rem;">
                                <strong>⚠️ Security Notice:</strong><br>
                                If you didn't request this code, please ignore this email or contact support immediately.
                            </p>
                        </div>
                        
                        <div style="border-top: 1px solid #eee; padding-top: 20px; text-align: center;">
                            <p style="color: #999; font-size: 0.85rem; margin: 0;">
                                © 2024 Lost & Found Portal - CSE447 Project<br>
                                Secure Authentication System
                            </p>
                        </div>
                    </div>
                </body>
            </html>
            """
            
            # Plain text fallback
            plain_text = f"""
Two-Factor Authentication - OTP Code
====================================

Hello {username},

Your One-Time Password (OTP) for secure login is:

    {otp_code}

⏰ This code is valid for {OTPManager.OTP_VALIDITY_SECONDS // 60} minutes only!

Do not share this code with anyone.
If you didn't request this code, please ignore this email.

Lost & Found Portal - CSE447 Project
            """
            
            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = OTPManager.SENDER_EMAIL
            message["To"] = recipient_email
            
            # Attach both plain text and HTML
            message.attach(MIMEText(plain_text, "plain"))
            message.attach(MIMEText(html_content, "html"))
            
            # Send email
            try:
                server = smtplib.SMTP(OTPManager.SMTP_SERVER, OTPManager.SMTP_PORT)
                server.starttls()
                server.login(OTPManager.SENDER_EMAIL, OTPManager.SENDER_PASSWORD)
                server.sendmail(OTPManager.SENDER_EMAIL, recipient_email, message.as_string())
                server.quit()
                
                print(f"✅ OTP email sent successfully to {recipient_email}")
                return True, "OTP sent to your email address"
            
            except smtplib.SMTPAuthenticationError:
                print("❌ Email authentication failed. Check sender email and password.")
                return False, "Email service configuration error. Please try again later."
            except smtplib.SMTPException as e:
                print(f"❌ SMTP error: {str(e)}")
                return False, f"Failed to send OTP: {str(e)}"
            except Exception as e:
                print(f"❌ Unexpected error: {str(e)}")
                return False, f"Error sending OTP: {str(e)}"
        
        except Exception as e:
            print(f"❌ Error preparing email: {str(e)}")
            return False, f"Error preparing email: {str(e)}"
    
    @staticmethod
    def get_otp_validity_remaining(email, db_path='lost_found.db'):
        """Get remaining time for OTP validity in seconds"""
        try:
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            
            result = c.execute('''
                SELECT expiration_time FROM otp_codes WHERE email = ?
            ''', (email,)).fetchone()
            
            conn.close()
            
            if not result:
                return None
            
            expiration_time = datetime.fromisoformat(result[0])
            remaining = (expiration_time - datetime.now()).total_seconds()
            
            return max(0, int(remaining))
        
        except Exception as e:
            print(f"❌ Error getting OTP validity: {str(e)}")
            return None
    
    @staticmethod
    def delete_otp(email, db_path='lost_found.db'):
        """Delete OTP from database"""
        try:
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute('DELETE FROM otp_codes WHERE email = ?', (email,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"❌ Error deleting OTP: {str(e)}")
            return False
