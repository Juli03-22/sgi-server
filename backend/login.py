import bcrypt
import pyotp
import os
import csv
import io
from colorama import init, Fore, Style
from cryptography.fernet import Fernet
from backend.audit import log_audit

init()

USERS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "users"))
DB_FILE = os.path.join(USERS_DIR, 'user_db.csv.enc')
KEY_FILE = os.path.join(USERS_DIR, 'keyfile.key')


prompts = {
    "menu_title": {
        "es": "*** Inicio de sesión SGI ***",
        "en": "*** SGI Login ***"
    },
    "user_prompt": {
        "es": "Usuario: ",
        "en": "Username: "
    },
    "pass_prompt": {
        "es": "Contraseña: ",
        "en": "Password: "
    },
    "user_not_found": {
        "es": "Usuario no encontrado.",
        "en": "User not found."
    },
    "pass_incorrect": {
        "es": "Contraseña incorrecta.",
        "en": "Incorrect password."
    },
    "totp_prompt": {
        "es": "Contraseña correcta. Ahora ingresa tu código OTP.",
        "en": "Password correct. Now enter your OTP code."
    },
    "otp_code": {
        "es": "Código OTP ({}/3): ",
        "en": "OTP code ({}/3): "
    },
    "otp_ok": {
        "es": "Inicio de sesión correcto",
        "en": "Login successful"
    },
    "otp_wrong": {
        "es": "OTP incorrecto.",
        "en": "Incorrect OTP."
    },
    "recovery": {
        "es": "Quieres intentar recuperar la cuenta? (simulación)\n",
        "en": "Do you want to try account recovery? (simulation)\n"
    },
    "locked": {
        "es": "\nDemasiados intentos fallidos. Acceso bloqueado temporalmente.",
        "en": "\nToo many failed attempts. Access temporarily locked."
    },
    "farewell": {
        "es": "Sesión cerrada",
        "en": "Session closed"
    },
    "login_options": {
        "es": "\nOpciones:\n1 - Cerrar sesión\n2 - Volver al login",
        "en": "\nOptions:\n1 - Log out\n2 - Return to login"
    },
    "login_option_prompt": {
        "es": "Selecciona opción: ",
        "en": "Select option: "
    },
    "invalid_option": {
        "es": "Opción no válida",
        "en": "Invalid option"
    }
}

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def load_key():
    with open(KEY_FILE, 'rb') as f:
        return f.read()

def descifrar_csv():
    key = load_key()
    fernet = Fernet(key)
    if not os.path.exists(DB_FILE):
        return []
    with open(DB_FILE, 'rb') as enc:
        data = fernet.decrypt(enc.read())
    f = io.StringIO(data.decode())
    reader = csv.DictReader(f)
    return list(reader)

def login_usuario(lang):
    def t(key):
        return prompts[key][lang]
    while True:
        clear()
        print(Fore.CYAN + t("menu_title") + Style.RESET_ALL)
        usuarios = descifrar_csv()
        intentos = 0
        while intentos < 5:
            username = input(t("user_prompt")).strip()
            password = input(t("pass_prompt")).strip()
            usuario = next((u for u in usuarios if u['username'] == username), None)
            if not usuario:
                print(Fore.RED + t("user_not_found") + Style.RESET_ALL)
                log_audit("LOGIN", user=username, status="FAILED", details="user not found")
                intentos += 1
                continue
            if not bcrypt.checkpw(password.encode(), usuario['hashed_password'].encode()):
                print(Fore.RED + t("pass_incorrect") + Style.RESET_ALL)
                log_audit("LOGIN", user=username, status="FAILED", details="bad password")
                intentos += 1
                continue
            print(t("totp_prompt"))
            for otp_intentos in range(3):
                otp_code = input(t("otp_code").format(otp_intentos+1)).strip()
                totp = pyotp.TOTP(usuario['otp_secret'])
                if totp.verify(otp_code, valid_window=2):
                    print(Fore.GREEN + t("otp_ok") + Style.RESET_ALL)
                    log_audit("LOGIN", user=username, status="SUCCESS")
                    while True:
                        print(Fore.CYAN + t("login_options") + Style.RESET_ALL)
                        op = input(t("login_option_prompt"))
                        if op == '1':
                            print(Fore.CYAN + t("farewell") + Style.RESET_ALL)
                            return
                        elif op == '2':
                            break  # Regresa al ciclo principal
                        else:
                            print(Fore.RED + t("invalid_option") + Style.RESET_ALL)
                    return
                else:
                    print(Fore.RED + t("otp_wrong") + Style.RESET_ALL)
                    log_audit("LOGIN", user=username, status="FAILED", details="badotp")
            print(Fore.YELLOW + t("recovery") + Style.RESET_ALL)
            intentos += 1
        print(Fore.RED + t("locked") + Style.RESET_ALL)
        break