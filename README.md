# SGI Server - Identity and Access Management System (IAM)

A complete authentication and user management system with strong security controls: multi-factor authentication (MFA), WebAuthn/FIDO2 physical keys, administrative approval workflow, role-based access, forced password rotation, session invalidation, and replay detection alerts.

## 🚀 Features

### Authentication and Security
- ✅ **Traditional login** (username + password)
- ✅ **Two-factor authentication (TOTP)** with QR provisioning
- ✅ **Physical security keys** WebAuthn/FIDO2 (YubiKey, etc.)
- ✅ **Role management** (user / administrator / root)
- ✅ **Administrative approval** for new registrations
- ✅ **Encrypted audit log** (hashed rows with IP & User-Agent metadata)
- ✅ **Time-based access control** (allowed hour window)
- ✅ **Forced password change** after admin reset (`must_change_password` flag)
- ✅ **Session invalidation** on role/password reset (`session_version` counter)
- ✅ **Secure role change workflow** (MFA challenge + last-root protection)
- ✅ **WebAuthn replay suspicion detection** (sign_count monitoring + alert)
- ✅ **Security alerts** table (out-of-hours & replay)

### User Management
- 👥 **Administration panel** (approve / delete / reset / manage roles)
- 🛠️ **Reset password with forced rotation flow**
- 🔄 **Role change with TOTP validation (admin/root)**
- 📝 **Personal data registration** (names, surnames, date of birth)
- 🔐 **Secure password generator**
- 🔄 **2FA secret regeneration**
- 🗝️ **WebAuthn key enrollment & listing**

### User Interface
- 🌐 **Responsive web interface** with Tailwind CSS
- 🌙 **Automatic dark mode**
- 🌍 **Multi-language support** (Spanish/English)
- 📱 **Mobile-responsive design**

## 🛠️ Technologies Used

- **Backend**: Python 3.x, Flask
- **Database**: SQLite3
- **Authentication**: bcrypt, pyotp, fido2
- **Frontend**: HTML5, Tailwind CSS, JavaScript
- **Security**: WebAuthn/FIDO2, TOTP, log encryption

## 📋 Requirements

### Python and Dependencies
```bash
Python 3.8+
Flask
bcrypt
pyotp
qrcode[pil]
fido2
cbor2
```

### Hardware (Optional)
- WebAuthn/FIDO2 compatible physical key (YubiKey, etc.)
- TOTP authentication app (Google Authenticator, Authy, etc.)

## ⚡ Installation and Setup

### Option 1: Docker Deployment (Recommended)

#### Prerequisites
- Docker Engine 20.10+
- Docker Compose 1.29+

#### Quick Start
```bash
# Clone the repository
git clone https://github.com/Juli03-22/sgi-server.git
cd sgi-server

# For Linux/Mac
chmod +x start-docker.sh
./start-docker.sh

# For Windows
start-docker.bat
```

#### Manual Docker Setup
```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f sgi-server

# Stop the service
docker-compose down
```

The server will be available at: `http://localhost:5000`

### Option 2: Traditional Installation

#### 1. Clone the repository
```bash
git clone https://github.com/Juli03-22/sgi-server.git
cd sgi-server
```

#### 2. Install dependencies
```bash
pip install -r requirements.txt
```

#### 3. Configure environment
Edit `config.py` with your configurations:
```python
SECRET_KEY = 'your_secret_key_here'
DB_PATH = 'database/db.sqlite3'
ALLOWED_HOURS = [6, 22]  # Allowed time: 6:00 AM - 10:00 PM
```

#### 4. Run the server
```bash
python app.py
```

The server will be available at: `http://127.0.0.1:5000`

## 📖 System Usage

### User Registration
1. Access `/register`
2. Complete user data and password
3. Complete personal information
4. Configure 2FA authentication by scanning the QR code
5. Wait for administrator approval

### Login
1. Enter username and password
2. Enter 2FA code if enabled
3. Alternatively, use WebAuthn physical key

If your password was reset by an administrator, you'll be redirected to a forced password change page before accessing any dashboard.

### Forced Password Change Flow
1. Admin triggers password reset → temporary random password is generated.
2. User logs in with temporary password.
3. System flags `must_change_password=1` and redirects to `/force_change_password`.
4. User submits old (temporary) password + new compliant password (policy enforced server-side).
5. On success: `must_change_password` cleared, normal session resumes.

### Role Change Workflow (Admin / Root)
1. Admin/root visits role change form.
2. Selects target role and provides THEIR OWN TOTP code (not target's).
3. Server validates constraints:
    - Cannot change own role.
    - Only root may alter another root.
    - Last remaining root cannot be demoted.
4. On success: user role updated, `session_version` increments (logs out other active sessions), audit logged.

### Physical Key Management
1. Go to `/webauthn/register` (after logging in)
2. Click "Register key"
3. Touch the physical key when prompted
4. The key will be registered for future logins

### Administration Panel
- **Users**: Approve, delete, reset passwords
- **Roles**: Assign permissions (user, admin, root)
- **Audit**: View access logs and activity
- **Alerts**: Monitor out-of-hours access attempts

## 🗂️ Project Structure

```
sgi-server/
├── app.py                 # Main application
├── app_mfa_routes.py      # MFA routes
├── config.py              # Configuration
├── README.md              # This file
├── LICENSE                # License
├── POLITICAS_IAM.md       # Security policies
├── auth/                  # Authentication module
│   ├── __init__.py
│   ├── login.py
│   └── models.py
├── database/              # Database
│   ├── __init__.py
│   └── db.sqlite3
├── templates/             # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── webauthn_register.html
│   └── ...
├── views/                 # Role-based views
│   ├── __init__.py
│   ├── admin_view.py
│   ├── root_view.py
│   └── user_view.py
└── web-app/               # Additional web application
    └── src/
```

## 🐳 Docker Configuration

### Environment Variables
The Docker container supports the following environment variables:

```yaml
FLASK_ENV=production          # Set to 'development' for debug mode
FLASK_HOST=0.0.0.0           # Host to bind to
FLASK_PORT=5000              # Port to bind to
SECRET_KEY=your_secret_key   # Application secret key
DB_PATH=/app/database/db.sqlite3  # Database path
```

### Volume Mounts
- `./database:/app/database` - Persists the SQLite database
- `./logs:/app/logs` - Persists application logs

### Docker Commands
```bash
# Build the image
docker build -t sgi-server .

# Run the container
docker run -d -p 5000:5000 -v ./database:/app/database sgi-server

# View container logs
docker logs -f <container_id>

# Stop and remove container
docker stop <container_id> && docker rm <container_id>
```

### Production Deployment
For production deployment, consider:
- Using a reverse proxy (nginx)
- Setting up SSL/TLS certificates
- Using a proper database (PostgreSQL, MySQL)
- Implementing container orchestration (Docker Swarm, Kubernetes)

## 🔧 Advanced Configuration

### Database
The system automatically initializes the necessary tables:
- `users` - User information
- `roles` - Role definitions
- `webauthn_credentials` - Physical key credentials
- `audit_log` - Encrypted audit logs
- `alerts` - Security alerts

Additional runtime auto-migration (idempotent) adds security columns:
- `users.must_change_password` (INTEGER 0/1) – forces password rotation after an admin reset.
- `users.session_version` (INTEGER) – increments on role or password reset; invalidates existing sessions.

### Security
- Passwords hashed with bcrypt
- Audit log entries hashed (with contextual IP / User-Agent) to deter tampering
- WebAuthn uses public key cryptography
- Origin / RP ID validation to prevent CSRF / origin spoofing
- Forced password rotation workflow enforced centrally
- Session version validation rejects stale sessions (user re-login required)
- WebAuthn `sign_count` replay suspicion generates alert (`webauthn_replay_suspect`)
- MFA required for admin/root role changes (admin authenticates themselves, not target)
- Protection against: last root removal, self role change, unauthorized root modifications

### Customization
- Modify `texts` in `app.py` to change languages
- Adjust `ALLOWED_HOURS` to control access schedules
- Customize styles in HTML templates

## 🐛 Troubleshooting

### Error: "OriginMissingDomain"
- Verify that `RP_ID` in `config.py` matches the domain used
- Always access through the same URL (127.0.0.1 or localhost)

### Error: "Cannot operate on a closed database"
- Restart the server
- Check write permissions in the `database/` directory

### Physical key not responding
- Verify that the browser supports WebAuthn
- Try in updated Chrome/Firefox
- Check that the key is properly connected

### "Sesión invalidada" / Session invalidated
Cause: Your role or password changed, or an admin reset your account. Log in again—this is a security measure (`session_version` mismatch).

### WebAuthn replay suspect alert
If a credential's `sign_count` does not increase between authentications, an alert row is created. Access is still granted (to reduce false positives) but administrators should review and potentially revoke the credential if repeated.

## 🧪 Recommended Hardening (Production)
- Enforce HTTPS (TLS) via reverse proxy (nginx / Caddy)
- Set cookies: `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_SAMESITE='Strict'`
- Add rate limiting (e.g. Flask-Limiter) to login, WebAuthn, role change, password reset
- Migrate from SQLite to PostgreSQL for integrity & concurrency
- Externalize and rotate secrets (env vars / secret manager)
- Centralize audit & alerts to SIEM (Elastic / Splunk)
- Add CSP & security headers (Flask-Talisman or custom middleware)
- Consider WebAuthn-only elevation for sensitive admin actions

## 📝 Contributing

1. Fork the project
2. Create feature branch (`git checkout -b feature/new-feature`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to branch (`git push origin feature/new-feature`)
5. Create Pull Request

## 📄 License

This project is under the MIT License. See the `LICENSE` file for details.

## 🤝 Support

To report issues or request features:
- Create an [Issue](https://github.com/Juli03-22/sgi-server/issues)
- Send Pull Request with improvements

## 👨‍💻 Authors

**Juli03-22**
- GitHub: [@Juli03-22](https://github.com/Juli03-22)
- 

**notyorch**
- GitHub: [@notyorch](https://github.com/notyorch)

---

⭐ If this project is useful to you, consider giving it a star on GitHub!