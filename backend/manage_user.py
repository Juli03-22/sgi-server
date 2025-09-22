import bcrypt
import os
import io
import csv
import pyotp
import qrcode
import sys
import json
from colorama import init, Fore, Style
from cryptography.fernet import Fernet
import secrets
from backend.audit import log_audit, show_audit_log
from backend.digital_signature import firmar_hash, verificar_firma

init()

USERS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "users"))
DB_FILE = os.path.join(USERS_DIR, 'user_db.csv.enc')
KEY_FILE = os.path.join(USERS_DIR, 'keyfile.key')
ROOT_TOTP_FILE = os.path.join(USERS_DIR, 'root_totp.txt')

prompts = {
    "root_setup": {
        "es": "*** Configuración de usuario root (primer uso) ***",
        "en": "*** Root user setup (first use) ***"
    },
    "root_scan": {
        "es": "Escanea el QR guardado en {path} o usa el secreto:\n{secret}",
        "en": "Scan the QR saved at {path} or use the secret:\n{secret}"
    },
    "root_app_ready": {
        "es": "Cuando tengas la app de autenticación lista, presiona Enter...",
        "en": "Once your authenticator app is ready, press Enter..."
    },
    "root_totp": {
        "es": "Introduce el código TOTP de root: ",
        "en": "Enter root's TOTP code: "
    },
    "root_ok": {
        "es": "Root autenticado correctamente.",
        "en": "Root authenticated successfully."
    },
    "root_error": {
        "es": "Demasiados intentos de root.",
        "en": "Too many root attempts."
    },
    "menu_title": {
        "es": "*** Gestión de identidades SGI (ROOT) ***",
        "en": "*** SGI Identity Management (ROOT) ***"
    },
    "menu_options": {
        "es": "1. Crear usuario root\n2. Consultar/listar usuarios\n3. Modificar datos personales\n4. Eliminar usuario\n5. Verificar integridad de usuario\n6. Cerrar sesión",
        "en": "1. Create root user\n2. List/consult users\n3. Modify user data\n4. Delete user\n5. Verify user integrity\n6. Log out"
    },
    "select_option": {
        "es": "Opción: ",
        "en": "Option: "
    },
    "create_root": {
        "es": "*** Crear usuario administrador (root) adicional ***",
        "en": "*** Create additional admin/root user ***"
    },
    "user_exists": {
        "es": "Nombre inválido o ya existe.",
        "en": "Invalid name or already exists."
    },
    "scan_add_qr": {
        "es": "Agrega este usuario root en tu app TOTP. Secreto: {secret}",
        "en": "Add this root user in your TOTP app. Secret: {secret}"
    },
    "continue": {
        "es": "Presiona Enter para continuar...",
        "en": "Press Enter to continue..."
    },
    "user_created": {
        "es": "Usuario root creado exitosamente!",
        "en": "Root user successfully created!"
    },
    "users_listed": {
        "es": "Usuarios en sistema (alfabético):",
        "en": "Users in the system (alphabetical):"
    },
    "user_select": {
        "es": "Selecciona usuario por número o nombre: ",
        "en": "Select user by number or name: "
    },
    "not_found": {
        "es": "Usuario no encontrado.",
        "en": "User not found."
    },
    "updated_ok": {
        "es": "Datos actualizados correctamente.",
        "en": "Data updated successfully."
    },
    "deleted_ok": {
        "es": "Usuario eliminado correctamente.",
        "en": "User deleted successfully."
    },
    "integrity_ok": {
        "es": "Integridad OK.",
        "en": "Integrity OK."
    },
    "integrity_fail": {
        "es": "¡Integridad VIOLADA! Los datos han sido modificados.",
        "en": "INTEGRITY VIOLATED! Data has been modified."
    },
    "logout": {
        "es": "Sesión root cerrada.",
        "en": "Root session closed."
    },
    "option_invalid": {
        "es": "Opción no válida.",
        "en": "Invalid option."
    }
}

def t(key, lang, **kwargs):
    s = prompts[key][lang]
    if kwargs:
        return s.format(**kwargs)
    return s

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def generar_o_cargar_clave():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    else:
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
    return key

def descifrar_csv():
    key = generar_o_cargar_clave()
    fernet = Fernet(key)
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
    with open(DB_FILE, 'wb') as fenc:
        fenc.write(fernet.encrypt(data))

def root_setup(lang):
    clear()
    print(Fore.CYAN + t("root_setup", lang) + Style.RESET_ALL)
    root_secret = pyotp.random_base32()
    with open(ROOT_TOTP_FILE, 'w') as f:
        f.write(root_secret)
    totp = pyotp.TOTP(root_secret)
    qr_uri = totp.provisioning_uri(name="root-admin", issuer_name="SGI-ROOT")
    qr_img = qrcode.make(qr_uri)
    qr_img_path = os.path.join(USERS_DIR, "root_qr.png")
    qr_img.save(qr_img_path)
    qr_img.show()
    qr_term = qrcode.QRCode()
    qr_term.add_data(qr_uri)
    qr_term.make()
    print("\n--- QR (ASCII, scan with authenticator app) ---\n")
    print(qr_term.print_ascii(invert=True))
    print("\n--- End QR ---\n")
    print(Fore.GREEN + t("root_scan", lang, path=qr_img_path, secret=root_secret) + Style.RESET_ALL)
    input(t("root_app_ready", lang))

def validar_root(lang):
    if not os.path.exists(ROOT_TOTP_FILE):
        root_setup(lang)
    with open(ROOT_TOTP_FILE) as f:
        root_secret = f.read().strip()
    totp = pyotp.TOTP(root_secret)
    for i in range(3):
        code = input(t("root_totp", lang))
        if totp.verify(code):
            print(Fore.GREEN + t("root_ok", lang) + Style.RESET_ALL)
            return True
        else:
            print(Fore.RED + t("option_invalid", lang) + Style.RESET_ALL)
    print(Fore.RED + t("root_error", lang) + Style.RESET_ALL)
    sys.exit(0)

def crear_usuario_root(lang):
    print(Fore.CYAN + t("create_root", lang) + Style.RESET_ALL)
    if not validar_root(lang):
        return
    usuarios = descifrar_csv()
    while True:
        username = input("Root username: ").strip()
        if not username or any(u['username'] == username for u in usuarios):
            print(Fore.RED + t("user_exists", lang) + Style.RESET_ALL)
            continue
        password = input("Root password: ").strip()
        otp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(otp_secret)
        qr_uri = totp.provisioning_uri(name=username, issuer_name="SGI-ROOT")
        qr_img = qrcode.make(qr_uri)
        qr_img_path = os.path.join(USERS_DIR, f'{username}_qr.png')
        qr_img.save(qr_img_path)
        qr_img.show()
        print(Fore.YELLOW + t("scan_add_qr", lang, secret=otp_secret) + Style.RESET_ALL)
        qr_term = qrcode.QRCode()
        qr_term.add_data(qr_uri)
        qr_term.make()
        print("\n--- QR (ASCII, scan with authenticator app) ---\n")
        print(qr_term.print_ascii(invert=True))
        print("\n--- End QR ---\n")
        input(t("continue", lang))
        datos_personales = {"nombre": input("First name(s): "), "apellido_paterno": input("Last name (paternal): "), "apellido_materno": input("Last name (maternal): "), "edad": input("Age: "), "rol": "root"}
        import hashlib
        datos_json = json.dumps(datos_personales, ensure_ascii=False)
        hash_bytes = hashlib.sha256(datos_json.encode()).digest()
        firma = firmar_hash(hash_bytes)
        usuarios.append({
            'username': username,
            'hashed_password': bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
            'personal_data': datos_json,
            'integrity_hash': hash_bytes.hex(),
            'signature': firma,
            'otp_secret': otp_secret,
            'role': 'root'
        })
        cifrar_csv(usuarios)
        print(Fore.GREEN + t("user_created", lang) + Style.RESET_ALL)
        break

def seleccionar_usuario(usuarios, lang):
    sorted_users = sorted(usuarios, key=lambda x: x['username'])
    for idx, u in enumerate(sorted_users):
        rol = u.get('role','user')
        print(Fore.GREEN + f"{idx+1}. {u['username']} ({rol})" + Style.RESET_ALL)
    s = input(t("user_select", lang))
    if s.isdigit():
        idx = int(s) - 1
        if 0 <= idx < len(sorted_users):
            return sorted_users[idx]
    else:
        for u in sorted_users:
            if u['username'] == s:
                return u
    print(Fore.RED + t("not_found", lang) + Style.RESET_ALL)
    return None

def listar_usuarios(usuarios, lang):
    print("\n" + Fore.CYAN + t("users_listed", lang) + Style.RESET_ALL)
    sorted_users = sorted(usuarios, key=lambda x: x['username'])
    for idx, u in enumerate(sorted_users):
        rol = u.get('role','user')
        datos = ""
        try:
            datos = json.loads(u["personal_data"])
            datos_show = f"{datos['nombre']} {datos['apellido_paterno']} {datos['apellido_materno']} ({datos['edad']}, {datos['rol']})"
        except:
            datos_show = u["personal_data"]
        print(Fore.GREEN + f"{idx+1}. {u['username']} [{rol}] - {datos_show}" + Style.RESET_ALL)
    print()

def modificar_datos(lang):
    usuarios = descifrar_csv()
    usuario = seleccionar_usuario(usuarios, lang)
    if not usuario:
        input(t("continue", lang))
        return
    datos_personales_str = usuario['personal_data']
    datos_personales = json.loads(datos_personales_str)
    nombre = input(f"First name(s) [{datos_personales['nombre']}]: ") or datos_personales['nombre']
    apellido_p = input(f"Last name (paternal) [{datos_personales['apellido_paterno']}]: ") or datos_personales['apellido_paterno']
    apellido_m = input(f"Last name (maternal) [{datos_personales['apellido_materno']}]: ") or datos_personales['apellido_materno']
    edad = input(f"Age [{datos_personales['edad']}]: ") or datos_personales['edad']
    rol = input(f"Role [{datos_personales['rol']}]: ") or datos_personales['rol']
    datos_actualizados = {
        "nombre": nombre,
        "apellido_paterno": apellido_p,
        "apellido_materno": apellido_m,
        "edad": edad,
        "rol": rol,
    }
    import hashlib
    datos_json = json.dumps(datos_actualizados, ensure_ascii=False)
    hash_bytes = hashlib.sha256(datos_json.encode()).digest()
    firma = firmar_hash(hash_bytes)
    usuario['personal_data'] = datos_json
    usuario['integrity_hash'] = hash_bytes.hex()
    usuario['signature'] = firma
    cifrar_csv(usuarios)
    log_audit("EDIT_USER", user=usuario['username'], details="edit personal data")
    print(Fore.GREEN + t("updated_ok", lang) + Style.RESET_ALL)

def eliminar_usuario(lang):
    usuarios = descifrar_csv()
    usuario = seleccionar_usuario(usuarios, lang)
    if not usuario:
        input(t("continue", lang))
        return
    usuarios = [u for u in usuarios if u['username'] != usuario['username']]
    cifrar_csv(usuarios)
    log_audit("DELETE_USER", user=usuario['username'])
    print(Fore.GREEN + t("deleted_ok", lang) + Style.RESET_ALL)

def verificar_integridad(lang):
    import hashlib
    usuarios = descifrar_csv()
    usuario = seleccionar_usuario(usuarios, lang)
    if not usuario:
        input(t("continue", lang))
        return
    datos = usuario['personal_data']
    hash_calculado = hashlib.sha256(datos.encode()).digest()
    firma = usuario.get("signature")
    if hash_calculado.hex() == usuario['integrity_hash'] and verificar_firma(hash_calculado, firma):
        print(Fore.GREEN + t("integrity_ok", lang) + Style.RESET_ALL)
    else:
        print(Fore.RED + t("integrity_fail", lang) + Style.RESET_ALL)

def menu_gestion(lang):
    validar_root(lang)
    while True:
        clear()
        print(Fore.CYAN + t("menu_title", lang) + Style.RESET_ALL)
        print(t("menu_options", lang))
        print("7. Ver auditoría/logs")
        op = input(Fore.GREEN + t("select_option", lang) + Style.RESET_ALL)
        if op == "1":
            crear_usuario_root(lang)
            input(t("continue", lang))
        elif op == "2":
            usuarios = descifrar_csv()
            listar_usuarios(usuarios, lang)
            input(t("continue", lang))
        elif op == "3":
            modificar_datos(lang)
            input(t("continue", lang))
        elif op == "4":
            eliminar_usuario(lang)
            input(t("continue", lang))
        elif op == "5":
            verificar_integridad(lang)
            input(t("continue", lang))
        elif op == "6":
            print(Fore.CYAN + t("logout", lang) + Style.RESET_ALL)
            break
        elif op == "7":
            show_audit_log()
            input("Presiona Enter para continuar...")
        else:
            print(Fore.RED + t("option_invalid", lang) + Style.RESET_ALL)
            input(t("continue", lang))

LANG = "es"

if __name__ == "__main__":
    try:
        LANG = os.environ["LANGUAGE"].split("_")[0][:2]
    except Exception:
        pass
    menu_gestion(LANG)