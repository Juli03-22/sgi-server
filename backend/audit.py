import os
import json
import datetime
from cryptography.fernet import Fernet

USERS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "users"))
LOGS_DIR = os.path.join(USERS_DIR, "logs")
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)
AUDIT_FILE = os.path.join(LOGS_DIR, "log_audit.enc")
KEY_FILE = os.path.join(USERS_DIR, 'keyfile.key')

def _get_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    else:
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
    return key

def log_audit(action: str, user: str = "-", status: str = "SUCCESS", details: str = ""):
    entry = {
        "datetime": datetime.datetime.now().isoformat(),
        "action": action,
        "user": user,
        "status": status,
        "details": details
    }
    entries = []
    key = _get_key()
    cipher = Fernet(key)
    if os.path.exists(AUDIT_FILE):
        # decrypt and get current log
        with open(AUDIT_FILE, 'rb') as f:
            try:
                decrypted = cipher.decrypt(f.read()).decode()
                entries = json.loads(decrypted)
            except Exception:
                entries = []
    entries.append(entry)
    # re-encrypt and save
    with open(AUDIT_FILE, "wb") as f:
        f.write(cipher.encrypt(json.dumps(entries, indent=2).encode()))

def show_audit_log():
    key = _get_key()
    cipher = Fernet(key)
    if not os.path.exists(AUDIT_FILE):
        print("No audit log yet.")
        return
    with open(AUDIT_FILE, 'rb') as f:
        decrypted = cipher.decrypt(f.read()).decode()
        log = json.loads(decrypted)
    for entry in log:
        print(f"[{entry['datetime']}] {entry['action']} | {entry['user']} | {entry['status']} | {entry['details']}")
