# Secure Identity Management System (SGI)

A robust, auditable, and CLI‑first system for user management, secure authentication, and personal data integrity — designed for academic and professional cybersecurity projects.

---

## Key Features

- **Terminal-based user lifecycle**: create, log in, manage users via an interactive menu
- **Secure password handling**: bcrypt with salt, never stored in plain text
- **Mandatory TOTP 2FA**: works with Google Authenticator, Authy, Aegis, and others
- **Personal data integrity**: SHA‑256 hashing with RSA digital signatures
- **Encrypted audit logging**: every sensitive event recorded (logins, creation, edits, QR use)
- **Full at-rest encryption**: user database and logs protected with Fernet (AES + HMAC)
- **Bilingual UI**: Spanish and English
- **Headless by design**: no GUI required; ASCII QR codes render in the terminal
- **SSH/remote friendly**: secure operations over SSH
- **Admin safeguards**: root/admin‑only for critical management and log review

---

## Project Structure

```
|-- main.py                  # Application entrypoint and main menu
|-- backend/
|   |-- add_user.py          # User creation workflow
|   |-- login.py           # Authentication and login flow
|   |-- manage_user.py      # Admin management and user lifecycle
|   |-- audit.py        # Encrypted action logging
|   |-- digital_signature.py # RSA signing for record integrity
|   |-- __init__.py
|-- users/                   # Encrypted DB, logs, crypto material, QR files
|   |-- user_db.csv.enc      # Encrypted user database
|   |-- keyfile.key          # Symmetric Fernet key (auto-generated)
|   |-- private_key.pem      # RSA private key (auto-generated)
|   |-- public_key.pem       # RSA public key (auto-generated)
|   |-- logs/
```

---

## Security Architecture

- **Passwords**: hashed and salted with bcrypt, stored only inside encrypted containers.
- **PII integrity**:
    - Each update generates a SHA‑256 hash.
    - The hash is signed with an auto‑generated RSA private key; both are stored for verification.
- **Audit logs**: all privileged or critical actions appended to an encrypted log (never in clear text).
- **TOTP/MFA**: login and registration require a valid TOTP code.
- **CLI‑first ops**: secure usage over SSH; plain files/services are never exposed.
- **Data at rest**: database and logs encrypted with Fernet (Python cryptography; AES with HMAC).

---

## Requirements

- Python 3.8+
- Pip modules: **bcrypt**, **cryptography**, **qrcode**, **pyotp**, **colorama**, **pyperclip**, **requests**, **pillow**

Install dependencies:

```bash
pip install bcrypt cryptography qrcode pyotp colorama pyperclip requests pillow
```

---

## How to Run

```bash
python main.py
```

- Choose your language on first run.
- Navigate the menu: Login, Add User, Manage Users (admin), or Exit.
- New users: follow prompts, copy the generated password, scan the QR with your authenticator app, and confirm the TOTP code.
- All actions are tracked securely and all data at rest remains encrypted.

---

## Usage

- **Add user**: creates a user with a strong password and provisions a TOTP secret.
- **Login**: validates password and TOTP before granting access.
- **Manage users (admin)**: reset credentials, deactivate/reactivate, review integrity, rotate keys (where applicable).

---

## Logging & Auditing

- All events are **encrypted** in `users/logs/log_audit.enc`.
- Only a root/admin can review audit logs.
- Sensitive fields (passwords, OTP secrets) are never written in clear text.

---

## Data Integrity & Compliance

- Any corruption or tampering of database files is flagged during integrity checks (hash or signature mismatch).
- Each audit entry includes action, actor, timestamp, and result.
- Security principles are documented in docstrings and comments.

---

## Digital Signatures

- Each user record’s data hash is **digitally signed** with the RSA private key.
- On edits and periodic checks, both the SHA‑256 hash and the signature are verified.
- Keypairs are auto‑generated and stored in `users/`. Keep the private key confidential.

---

## TOTP, QR, and SSH

- TOTP secrets are encoded into QR codes that render as **ASCII** directly in the terminal.
- Works seamlessly over SSH, WSL, and cloud environments.
- No HTTP surface is exposed.

---

## Recommended Practices

- Periodically back up the `users/` folder (encrypted DB and keys).
- If the private key or Fernet key is compromised, rotate/regenerate them following in‑code instructions.
- Avoid running on untrusted or compromised machines.
- Do not expose system files or folders via public HTTP/S sharing.

---

## FAQ

**What if I manually edit or corrupt the encrypted DB?**

SGI detects unauthorized changes by verifying stored SHA‑256 hashes and digital signatures. Tampered records are rejected.

**Is this suitable for real‑world production?**

With minor operational adjustments (e.g., retention policies) and appropriate controls, yes. The system follows real‑world security and auditing best practices.

---

## Authors

**Project author**

Julieta Lizeth Carrillo Hernández

TSU in Network Security — Universidad Politécnica de Yucatán

**Additional assignment support**

Jorge Enrique Vargas Pech

TSU in Data Science — Universidad Politécnica de Yucatán

Mérida, México — September 2025

---

## License

MIT‑style license for academic demonstration and research use.

Not for direct commercial production without further professional review.
