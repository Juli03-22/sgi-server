# SGI Server - Identity and Access Management System (IAM)

A complete authentication and user management system with support for multi-factor authentication (MFA) and WebAuthn/FIDO2 physical keys.

## 🚀 Features

### Authentication and Security
- ✅ **Traditional login system** with username and password
- ✅ **Two-factor authentication (2FA)** with TOTP codes
- ✅ **Physical key support** WebAuthn/FIDO2 (YubiKey, etc.)
- ✅ **Role management** (user, administrator, root)
- ✅ **User approval system** for new registrations
- ✅ **Access auditing** with encrypted logs
- ✅ **Time-based access control**

### User Management
- 👥 **Complete administration panel**
- 📝 **Personal data registration** (names, surnames, date of birth)
- 🔐 **Secure password generator**
- 🔄 **2FA code regeneration**
- 🗝️ **WebAuthn physical key management**

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

## � Docker Configuration

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

## �🔧 Advanced Configuration

### Database
The system automatically initializes the necessary tables:
- `users` - User information
- `roles` - Role definitions
- `webauthn_credentials` - Physical key credentials
- `audit_log` - Encrypted audit logs
- `alerts` - Security alerts

### Security
- Passwords are stored with bcrypt hash
- Audit logs are encrypted
- WebAuthn uses public key cryptography
- Origin validation to prevent CSRF attacks

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