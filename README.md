# 🔍 Lost & Found Portal

A secure, full-featured web application for posting and claiming lost/found items with enterprise-grade encryption and two-factor authentication.

---

## 📋 Quick Start

### Installation
```bash
pip install -r requirements.txt
python app.py
```

### Access
- **App:** http://localhost:5000
- **Admin Login:** `admin` / `admin123` (from `.env`)

### Create New Account
1. Visit http://localhost:5000/register
2. Fill in username, email, password
3. Click "Create Account"
4. Login with your new credentials

---

## 🔐 Key Features

### 1. **Two-Factor Authentication (2FA)**
- Email-based OTP verification
- 6-digit random codes, 5-minute expiration
- One-time use enforcement
- SMTP TLS encryption

### 2. **Multi-Layer Encryption**
- Custom RSA encryption (asymmetric)
- Custom ECC encryption (elliptic curve)
- Custom HMAC-SHA256 (data integrity)
- Prevents data tampering & interception

### 3. **User Management**
- Secure password hashing (SHA-256)
- Profile editing with password verification
- Username & email editable
- Session isolation & auto-cleanup

### 4. **Security Best Practices**
- SQL injection protection (parameterized queries)
- CSRF token validation
- Encrypted session cookies
- Database automatic cleanup

---

## 📁 Project Structure

```
lost_found_portal/
├── app.py                   # Flask application (main)
├── .env                     # Configuration (⚠️ keep private)
├── .env.example             # Template for .env
├── .gitignore               # Prevents committing secrets
├── requirements.txt         # Python dependencies
├── README.md                # This file
│
├── static/
│   ├── style.css            # Global styles
│   └── uploads/             # User uploaded images
│
├── templates/
│   ├── base.html            # Navigation & layout
│   ├── login.html           # Login page
│   ├── register.html        # Registration page
│   ├── verify_otp.html      # OTP verification
│   ├── dashboard.html       # Main dashboard
│   ├── profile.html         # User profile view
│   ├── profile_edit.html    # Edit profile
│   ├── post_item.html       # Post lost/found item
│   └── [more templates]
│
├── utils/
│   ├── auth.py              # Authentication utilities
│   ├── file_handler.py      # File upload handling
│   ├── otp.py               # OTP generation & email
│   └── __init__.py          # Package imports
│
└── crypto/
    ├── rsa_custom.py        # Custom RSA encryption
    ├── ecc_custom.py        # Custom ECC encryption
    ├── hmac_custom.py       # Custom HMAC verification
    ├── multi_encrypt.py     # Multi-layer encryption
    ├── key_manager.py       # Key management
    ├── two_factor.py        # 2FA utilities
    └── verification.py      # Cryptographic verification
```

---

## 🔧 Configuration

### Environment Variables (`.env`)
```env
# Flask
FLASK_SECRET_KEY=your-secret-key
FLASK_ENV=development
DEBUG=True

# Email (2FA)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your-email@gmail.com
SENDER_PASSWORD=your-app-password

# OTP
OTP_LENGTH=6
OTP_VALIDITY_SECONDS=300

# Admin
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=admin123
```

### Using Different Email Providers

**Gmail:**
```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your-email@gmail.com
SENDER_PASSWORD=16-char-app-password
```

---

## 👤 User Management

### Admin Account
- **Username:** `admin` (editable)
- **Password:** `admin123` (from `.env`)
- **Email:** `projectowner478@gmail.com` (from `.env`)
- **Auto-created** on first app run

### Edit Profile
1. Login to your account
2. Click username in header → Profile
3. Click "Edit Profile"
4. Change username, email, or full name
5. Enter password to confirm
6. Save changes
7. **Use new username for next login**

---

## 🔒 Security Features

| Feature | Details |
|---------|---------|
| **Password Hashing** | SHA-256 hashing, never stored as plain text |
| **2FA** | Email OTP, 6 digits, 5-min expiration |
| **Encryption** | RSA + ECC multi-layer encryption |
| **Data Integrity** | HMAC-SHA256 verification |
| **SQL Injection** | Parameterized queries everywhere |
| **CSRF Protection** | Token validation on all forms |
| **Session Security** | Encrypted cookies, auto-expiration |
| **Email Security** | SMTP TLS encryption |

---

## 🎯 Core Routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Home page |
| `/login` | GET, POST | User login |
| `/register` | GET, POST | New user registration |
| `/verify-otp` | GET, POST | OTP verification |
| `/dashboard` | GET | User dashboard |
| `/profile` | GET | View profile |
| `/profile/edit` | GET, POST | Edit profile (username, email, name) |
| `/post` | GET, POST | Post lost/found item |
| `/items` | GET | Browse items |
| `/claim/<id>` | GET, POST | File claim for item |
| `/logout` | GET | Logout user |

---

## 🚀 Deployment

### Development
```bash
python app.py
# App runs on http://localhost:5000
```

### Production
1. Update `.env` for production:
   ```env
   FLASK_ENV=production
   DEBUG=False
   FLASK_SECRET_KEY=generate-new-strong-key
   ```

2. Use production WSGI server:
   ```bash
   pip install gunicorn
   gunicorn -w 4 app:app
   ```

3. Enable HTTPS/SSL
4. Update email credentials for production
5. Set strong admin password

---

## 🛠️ Troubleshooting

**Register page error?**
- Check that `register.html` template exists
- Verify database is initialized

**Email not sending?**
- Check `.env` has correct email credentials
- Verify SMTP server and port are correct
- For Gmail: Use 16-character app password, not your regular password

**Can't login after changing username?**
- Use your NEW username (from profile edit)
- Old username no longer works

**Database errors?**
- Delete `lost_found.db` to reset
- App will auto-recreate on next run

---

## 📦 Dependencies

- **Flask** (web framework)
- **SQLite3** (database)
- **python-dotenv** (environment variables)
- **cryptography** (secure operations)
- **Pillow** (image handling)
- **sympy** (prime number generation)

See `requirements.txt` for full list.

---

## 📝 File Descriptions

| File | Purpose |
|------|---------|
| **app.py** | Main Flask application with all routes |
| **utils/otp.py** | OTP generation, email sending, verification |
| **utils/auth.py** | Login/registration authentication |
| **crypto/* | Custom encryption implementations |
| **.env** | Confidential configuration (DO NOT COMMIT) |
| **.gitignore** | Prevents committing sensitive files |
| **requirements.txt** | Python package dependencies |

---

## ⚠️ Important Security Notes

1. **Never commit `.env`** - Contains passwords and secrets
2. **Change admin password** in `.env` for production
3. **Use HTTPS** in production (DEBUG=False)
4. **Generate new SECRET_KEY** for production
5. **Keep `.env` file secure** - Limit file permissions
6. **Rotate credentials** periodically
7. **Use strong passwords** for all accounts

---

## 🎨 Customization

### Change Brand Colors
Edit `templates/base.html` or `static/style.css`

### Modify OTP Timeout
Update `.env`:
```env
OTP_VALIDITY_SECONDS=600  # 10 minutes instead of 5
```

### Change Email Template
Edit email content in `utils/otp.py` method `send_otp_email()`

### Customize Admin Account
Update `.env` and restart app:
```env
ADMIN_USERNAME=your-admin-name
ADMIN_EMAIL=your-admin-email@example.com
ADMIN_PASSWORD=your-secure-password
```

---

## 📊 Database Schema

### Users Table
- `id` - Unique identifier
- `username` - Login username (unique)
- `password_hash` - SHA-256 hashed password
- `email` - Email address
- `full_name` - Display name
- `role` - User role (user/admin)
- `created_at` - Account creation timestamp
- `last_login` - Last login time

### Items Table
- `id` - Unique identifier
- `user_id` - Posted by user
- `title` - Item title
- `description` - Item details
- `location` - Where found/lost
- `item_type` - Type of item
- `category` - Category
- `photo_path` - Image path
- `status` - Item status
- `created_at` - Post timestamp

### OTP Codes Table
- `id` - Unique identifier
- `email` - User email
- `otp_code` - 6-digit code
- `expiration_time` - Code expiration
- `created_at` - Creation timestamp

---

## 🤝 Support

For issues or questions:
1. Check troubleshooting section above
2. Review error messages in console
3. Check `.env` configuration
4. Verify database connectivity

---

## 📄 License

This project is part of CSE447 coursework.

---

## ✨ Version Info

- **Framework:** Flask 2.3.3
- **Database:** SQLite3
- **Python:** 3.7+
- **Last Updated:** January 2026

---

**Your Lost & Found Portal is ready to use! 🎉**

