import re
import bcrypt
import secrets
import string
import pyotp
import qrcode
import pyperclip
import os
import io
import csv
import json
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
import hashlib
from colorama import init, Fore, Style
import platform

from cryptography.fernet import Fernet
from backend.audit import log_audit
from backend.digital_signature import firmar_hash

init()

is_windows = platform.system().lower() == "windows"

USERS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "users"))
if not os.path.exists(USERS_DIR):
    os.makedirs(USERS_DIR)

ROLES = [
    ("Finanzas", "Finance"),
    ("Recursos Humanos", "Human Resources"),
    ("TI", "IT"),
    ("Administrativo", "Administrative"),
    ("Operaciones", "Operations"),
    ("Marketing", "Marketing"),
    ("Ventas", "Sales"),
    ("Legal", "Legal"),
    ("Otro", "Other")
]

prompts = {
    "menu_title": {
        "es": "\n*** Menú de Creación de Usuarios SGI ***",
        "en": "\n*** SGI User Creation Menu ***"
    },
    "menu_options": {
        "es": "\n1: Crear usuario\n2: Salir",
        "en": "\n1: Create user\n2: Exit"
    },
    "select_option": {
        "es": "Selecciona una opción: ",
        "en": "Select an option: "
    },
    "exit_msg": {
        "es": "Saliendo del sistema...",
        "en": "Exiting the system..."
    },
    "create_user": {
        "es": "*** Crear usuario ***",
        "en": "*** Create user ***"
    },
    "input_username": {
        "es": "Ingrese el nombre de usuario: ",
        "en": "Enter username: "
    },
    "invalid_username": {
        "es": "Usuario inválido. Usa solo letras, números, @ _ - . , (sin espacios, ñ, etc)",
        "en": "Invalid username. Use only letters, numbers, @ _ - . , (no spaces, ñ, etc)"
    },
    "retry": {
        "es": "¿Volver a intentar?",
        "en": "Retry?"
    },
    "cancelled": {
        "es": "Cancelado. Regresando al menú principal...",
        "en": "Cancelled. Returning to main menu..."
    },
    "pass_title": {
        "es": "*** Generando contraseña segura ***\n",
        "en": "*** Generating secure password ***\n"
    },
    "pass_generated": {
        "es": "Contraseña generada: ",
        "en": "Generated password: "
    },
    "pass_copy": {
        "es": "Contraseña copiada al portapapeles.",
        "en": "Password copied to clipboard."
    },
    "pass_options": {
        "es": "1: Copiar al portapapeles\n2: Generar otra\n3: Confirmar\n4: Ir atrás",
        "en": "1: Copy to clipboard\n2: Generate another\n3: Confirm\n4: Go back"
    },
    "clipboard_option_unavailable": {
        "es": "La opción de portapapeles no está disponible en este sistema.",
        "en": "Clipboard option not available on this system."
    },
    "press_enter": {
        "es": "Presiona Enter para continuar...",
        "en": "Press Enter to continue..."
    },
    "otp_config": {
        "es": "*** Configuración de doble factor (TOTP) ***",
        "en": "*** Two-factor configuration (TOTP) ***"
    },
    "otp_secret": {
        "es": "OTP SECRET: ",
        "en": "OTP SECRET: "
    },
    "otp_menu": {
        "es": "1: Mostrar QR en terminal (ASCII)\n2: Ingresar código OTP de la app\n3: Ir atrás",
        "en": "1: Show QR in terminal (ASCII)\n2: Enter OTP code from app\n3: Go back"
    },
    "otp_ipinfo": {
        "es": "Para ver el QR, abre el navegador y entra a: ",
        "en": "To see the QR, open your browser and go to: "
    },
    "otp_qr_note": {
        "es": "Escanea el código QR mostrado.",
        "en": "Scan the shown QR code."
    },
    "otp_ok": {
        "es": "¡OTP verificado correctamente!",
        "en": "OTP successfully verified!"
    },
    "otp_fail": {
        "es": "Código OTP no válido. Intente de nuevo.",
        "en": "Invalid OTP code. Try again."
    },
    "back_confirm": {
        "es": "¿Seguro que quieres volver atrás? Se perderán tus datos.",
        "en": "Are you sure you want to go back? Your data will be lost."
    },
    "personal_title": {
        "es": "=== Datos personales a proteger ===",
        "en": "=== Personal data to protect ==="
    },
    "nombre": {
        "es": "Nombre(s): ",
        "en": "First name(s): "
    },
    "apellido_paterno": {
        "es": "Apellido paterno: ",
        "en": "Last name (paternal): "
    },
    "apellido_materno": {
        "es": "Apellido materno: ",
        "en": "Last name (maternal): "
    },
    "edad": {
        "es": "Edad: ",
        "en": "Age: "
    },
    "edad_invalid": {
        "es": "Edad no válida.",
        "en": "Invalid age."
    },
    "role_select": {
        "es": "Selecciona el rol del usuario:",
        "en": "Select the user's role:"
    },
    "role_option": {
        "es": "Rol [número]: ",
        "en": "Role [number]: "
    },
    "role_invalid": {
        "es": "Opción inválida.",
        "en": "Invalid option."
    },
    "saved_ok": {
        "es": "\nDatos registrados correctamente.",
        "en": "\nData registered successfully."
    }
}

def t(key, lang):
    return prompts[key][lang]

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def generar_o_cargar_clave():
    KEY_FILE = os.path.join(USERS_DIR, 'keyfile.key')
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    else:
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
    return key

def get_db_file():
    return os.path.join(USERS_DIR, 'user_db.csv.enc')

def descifrar_csv():
    key = generar_o_cargar_clave()
    fernet = Fernet(key)
    DB_FILE = get_db_file()
    if not os.path.exists(DB_FILE):
        return []
    with open(DB_FILE, 'rb') as enc:
        data = fernet.decrypt(enc.read())
    f = io.StringIO(data.decode())
    reader = csv.DictReader(f)
    return list(reader)

def cifrar_csv(usuarios):
    key = generar_o_cargar_clave()
    fernet = Fernet(key)
    output = io.StringIO()
    headers = [
        'username','hashed_password','personal_data','integrity_hash','signature','otp_secret','role'
    ]
    writer = csv.DictWriter(output, fieldnames=headers)
    writer.writeheader()
    writer.writerows(usuarios)
    data = output.getvalue().encode()
    DB_FILE = get_db_file()
    with open(DB_FILE, 'wb') as fenc:
        fenc.write(fernet.encrypt(data))

def limpiar_usuario(usuario):
    return usuario.strip()

def usuario_valido(usuario):
    patron = r'^[a-zA-Z0-9@\-_.,]+$'
    return re.fullmatch(patron, usuario) and ' ' not in usuario

def generar_contraseña(largo=32):
    chars = string.ascii_letters + string.digits + "@#%^*.,-_"
    return ''.join(secrets.choice(chars) for _ in range(largo))

def confirmar(mensaje):
    entrada = input(Fore.YELLOW + f"{mensaje} (s/n): " + Style.RESET_ALL)
    return entrada.lower().startswith('s')

def pedir_datos_personales(lang):
    clear()
    print(Fore.CYAN + t("personal_title", lang) + Style.RESET_ALL)
    nombre = input(t("nombre", lang))
    apellido_paterno = input(t("apellido_paterno", lang))
    apellido_materno = input(t("apellido_materno", lang))
    while True:
        edad = input(t("edad", lang))
        if edad.isdigit() and 0 < int(edad) < 130:
            break
        print(Fore.RED + t("edad_invalid", lang) + Style.RESET_ALL)
    print(Fore.CYAN + "\n" + t("role_select", lang) + Style.RESET_ALL)
    for i, rol in enumerate(ROLES):
        print(f"{i+1}. {rol[lang == 'en']}")
    while True:
        rol_idx = input(t("role_option", lang))
        if rol_idx.isdigit() and 1 <= int(rol_idx) <= len(ROLES):
            rol = ROLES[int(rol_idx)-1][lang == 'en']
            break
        print(Fore.RED + t("role_invalid", lang) + Style.RESET_ALL)
    return {
        "nombre": nombre.strip(),
        "apellido_paterno": apellido_paterno.strip(),
        "apellido_materno": apellido_materno.strip(),
        "edad": int(edad),
        "rol": rol
    }, rol

def get_user_dir(username):
    h = hashlib.sha256(username.encode()).hexdigest()
    user_dir = os.path.join(USERS_DIR, h)
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
    return user_dir

def serve_qr_html(qr_path, port=8000, ip='0.0.0.0'):
    class QRHandler(SimpleHTTPRequestHandler):
        def do_GET(self):
            img_name = os.path.basename(qr_path)
            if self.path == '/' or self.path.startswith('/?'):
                # Main QR page
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                html = f'''
                <html>
                  <body>
                    <h1>Scan this QR code:</h1>
                    <img src="/{img_name}" style="width:300px;">
                  </body>
                </html>
                '''
                self.wfile.write(html.encode("utf-8"))
            elif self.path == '/' + img_name:
                # Serve the image data
                self.send_response(200)
                self.send_header("Content-type", "image/png")
                self.end_headers()
                with open(qr_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404)

        def log_message(self, format, *args):
            return

    cwd = os.getcwd()
    os.chdir(os.path.dirname(qr_path))
    httpd = HTTPServer((ip, port), QRHandler)
    t = threading.Thread(target=httpd.serve_forever)
    t.daemon = True
    t.start()
    os.chdir(cwd)
    return httpd, port


def menu_creacion_usuario(lang):
    clear()
    print(Fore.CYAN + Style.BRIGHT + t("menu_title", lang) + Style.RESET_ALL)
    while True:
        print(Fore.GREEN + t("menu_options", lang) + Style.RESET_ALL)
        opcion = input(t("select_option", lang))
        if opcion == '1':
            flujo_agregar_usuario(lang)
        elif opcion == '2':
            print(Fore.CYAN + t("exit_msg", lang) + Style.RESET_ALL)
            break
        else:
            print(Fore.RED + t("role_invalid", lang) + Style.RESET_ALL)

def flujo_agregar_usuario(lang):
    while True:
        clear()
        print(Fore.CYAN + t("create_user", lang) + Style.RESET_ALL)
        usuario = limpiar_usuario(input(t("input_username", lang)))
        if not usuario_valido(usuario):
            print(Fore.RED + t("invalid_username", lang) + Style.RESET_ALL)
            if not confirmar(t("retry", lang)):
                print(Fore.YELLOW + t("cancelled", lang) + Style.RESET_ALL)
                return
            continue
        break

    password = generar_contraseña()
    confirmed = False
    while not confirmed:
        clear()
        print(Fore.CYAN + t("pass_title", lang) + Style.RESET_ALL)
        print(Fore.GREEN + t("pass_generated", lang) + password + Style.RESET_ALL)
        
        options_str = t("pass_options", lang)
        options = options_str.splitlines()

        if is_windows:
            print(options[0])
        
        print(options[1])
        print(options[2])
        print(options[3])

        op = input(t("select_option", lang))
        if op == '1':
            if is_windows:
                pyperclip.copy(password)
                print(Fore.YELLOW + t("pass_copy", lang) + Style.RESET_ALL)
                input(t("press_enter", lang))
            else:
                print(Fore.RED + t("clipboard_option_unavailable", lang) + Style.RESET_ALL)
                input(t("press_enter", lang))
        elif op == '2':
            password = generar_contraseña()
        elif op == '3':
            confirmed = True
        elif op == '4':
            if confirmar(t("back_confirm", lang)):
                return
        else:
            print(Fore.RED + t("role_invalid", lang) + Style.RESET_ALL)
            input(t("press_enter", lang))

    otp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(otp_secret)
    qr_uri = totp.provisioning_uri(name=usuario, issuer_name="SGI-Seguro")
    user_dir = get_user_dir(usuario)
    qr_path = os.path.join(user_dir, f'{usuario}_qr.png')

    qr_img = qrcode.make(qr_uri)
    qr_img.save(qr_path)
    otp_confirmed = False

    while not otp_confirmed:
        clear()
        print(Fore.CYAN + t("otp_config", lang) + Style.RESET_ALL)
        print(t("otp_secret", lang) + Fore.GREEN +otp_secret + Style.RESET_ALL + "\n")
        print(t("otp_menu", lang))
        op = input(t("select_option", lang))
        if op == "1":
            qr_term = qrcode.QRCode()
            qr_term.add_data(qr_uri)
            qr_term.make()
            print(qr_term.print_ascii(invert=True))
            log_audit("SHOW_QR", user=usuario, details="terminal")
            print(Fore.YELLOW + t("otp_qr_note", lang) + Style.RESET_ALL)
            input(t("press_enter", lang))
        elif op == "2":
            otp_input = input("OTP: ")
            if totp.verify(otp_input, valid_window=2):
                print(Fore.GREEN + t("otp_ok", lang) + Style.RESET_ALL)
                otp_confirmed = True
                if os.path.exists(qr_path):
                    os.remove(qr_path)
                try:
                    os.rmdir(user_dir)
                except OSError:
                    pass
                input(t("press_enter", lang))
            else:
                print(Fore.RED + t("otp_fail", lang) + Style.RESET_ALL)
                log_audit("TOTP_FAIL", user=usuario)
                input(t("press_enter", lang))
        elif op == "3":
            if confirmar(t("back_confirm", lang)):
                return
        else:
            print(Fore.RED + t("role_invalid", lang) + Style.RESET_ALL)
            input(t("press_enter", lang))


    datos_dict, rol = pedir_datos_personales(lang)
    datos_personales = json.dumps(datos_dict, ensure_ascii=False)
    hash_bytes = hashlib.sha256(datos_personales.encode()).digest()
    firma = firmar_hash(hash_bytes)
    hash_hex = hash_bytes.hex()

    usuarios = descifrar_csv()
    usuarios.append({
        'username': usuario,
        'hashed_password': bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
        'personal_data': datos_personales,
        'integrity_hash': hash_hex,
        'signature': firma,
        'otp_secret': otp_secret,
        'role': rol
    })
    cifrar_csv(usuarios)
    log_audit("REGISTER_USER", user=usuario)
    print(Fore.GREEN + t("saved_ok", lang) + Style.RESET_ALL)
    input(t("press_enter", lang))

LANG = "es"

if __name__ == "__main__":
    try:
        LANG = os.environ["LANGUAGE"].split("_")[0][:2]
    except Exception:
        pass
    menu_creacion_usuario(LANG)