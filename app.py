

import pyotp
import json
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialDescriptor,
    AttestationObject,
    CollectedClientData,
    AuthenticatorData,
)
from fido2.utils import websafe_encode, websafe_decode
import cbor2 as cbor
from flask import make_response

# Configuración WebAuthn
RP_ID = "127.0.0.1"
RP_NAME = "SGI IAM"
ORIGINS = ["http://127.0.0.1:5000"]
rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
fido2_server = Fido2Server(rp)

import pyotp
import qrcode
import io
import base64
import hashlib
import datetime
import bcrypt
from functools import wraps
from config import Config

from flask import Flask, render_template, render_template_string, request, redirect, session, url_for, jsonify, flash
import sqlite3
import os
import random
import string

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
ALLOWED_HOURS = Config.ALLOWED_HOURS
def get_db_connection():
    conn = sqlite3.connect(Config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Helper seguro para filas sqlite3.Row
def safe_row_value(row, key, default=None):
    try:
        if row is None:
            return default
        return row[key]
    except Exception:
        return default

# --- Seguridad: asegurar columnas nuevas (idempotente) ---
def ensure_schema():
    conn = get_db_connection()
    try:
        conn.execute('ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0')
    except Exception:
        pass
    try:
        conn.execute('ALTER TABLE users ADD COLUMN session_version INTEGER DEFAULT 0')
    except Exception:
        pass
    conn.commit(); conn.close()

ensure_schema()

# Inicializar tabla WebAuthn si no existe
def init_webauthn_table():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            credential_id TEXT NOT NULL UNIQUE,
            public_key TEXT NOT NULL,
            sign_count INTEGER DEFAULT 0,
            transports TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

# Inicializar tabla al cargar la aplicación
init_webauthn_table()

# Función para cifrar (hash) los logs de auditoría
SECRET_LOG_KEY = 'clave_secreta_audit'  # Cambia esto por una clave segura

def encrypt_log(text):
    # Simple hash+base64 para ejemplo, usa cifrado fuerte en producción
    h = hashlib.sha256((SECRET_LOG_KEY + text).encode()).digest()
    return base64.b64encode(h).decode()

# Modificar log_audit para guardar hash

def log_audit(user_id, action, details=None):
    raw = f"{user_id}|{action}|{details if details else ''}"
    try:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        ua = request.headers.get('User-Agent', '-')
        raw = raw + f"|IP={ip}|UA={ua[:120]}"
    except Exception:
        pass
    encrypted = encrypt_log(raw)
    conn = get_db_connection()
    conn.execute('INSERT INTO audit_log (user_id, action) VALUES (?, ?)', (user_id, encrypted))
    conn.commit()
    conn.close()

# Diccionario de textos para los dos idiomas
texts = {
    'es': {
        'login': 'Iniciar sesión',
        'register': 'Registrarse',
        'username': 'Usuario',
        'password': 'Contraseña',
        'submit': 'Enviar',
        'change_lang': 'Cambiar a inglés',
        'already_user': '¿Ya tienes cuenta? Inicia sesión',
        'no_account': '¿No tienes cuenta? Regístrate',
        'incorrect': 'Usuario o contraseña incorrectos',
        'user_exists': 'El usuario ya existe',
        'welcome_user': 'Bienvenido, usuario normal',
        'welcome_admin': 'Bienvenido, administrador',
        'welcome_root': 'Bienvenido, root',
        'logout': 'Cerrar sesión',
        'password_requirements': 'La contraseña debe tener al menos 16 caracteres, mayúsculas, minúsculas, números y símbolos.',
        'suggest_password': 'Sugerir contraseña',
        'copy': 'Copiar',
        '2fa_title': 'Autenticación de dos factores',
        '2fa_instruction': 'Escanea el código QR con tu app de autenticación o ingresa el código de seguridad:',
        '2fa_code': 'Código de seguridad',
        '2fa_submit': 'Verificar',
        '2fa_error': 'Código incorrecto. Intenta de nuevo.',
        'admin_panel': 'Panel de Administración',
        'current_user': 'Usuario actual:',
        'role': 'rol',
        'status': 'Estado',
        'actions': 'Acciones',
        'approved': 'Aprobado',
        'pending': 'Pendiente',
        'approve': 'Aprobar',
        'delete': 'Eliminar',
        'reset_password': 'Resetear contraseña',
        'change_role': 'Cambiar rol',
        'new_role': 'Nuevo rol',
        'admin_mfa_code': 'Código MFA (admin/root)',
        'role_changed': 'Rol actualizado correctamente',
        'mfa_required_role_change': 'Debes habilitar 2FA para cambiar roles',
        'mfa_invalid': 'Código MFA inválido',
        'cannot_change_own_role': 'No puedes cambiar tu propio rol',
        'cannot_change_root_without_root': 'Solo un usuario root puede cambiar el rol de otro root',
        'cannot_remove_last_root': 'No puedes eliminar el último usuario con rol root'
    },
    'en': {
        'login': 'Login',
        'register': 'Register',
        'username': 'Username',
        'password': 'Password',
        'submit': 'Submit',
        'change_lang': 'Switch to Spanish',
        'already_user': 'Already have an account? Login',
        'no_account': "Don't have an account? Register",
        'incorrect': 'Incorrect username or password',
        'user_exists': 'User already exists',
        'welcome_user': 'Welcome, regular user',
        'welcome_admin': 'Welcome, admin',
        'welcome_root': 'Welcome, root',
        'logout': 'Logout',
        'password_requirements': 'Password must be at least 16 characters, with uppercase, lowercase, numbers, and symbols.',
        'suggest_password': 'Suggest password',
        'copy': 'Copy',
        '2fa_title': 'Two-Factor Authentication',
        '2fa_instruction': 'Scan the QR code with your authenticator app or enter the security code:',
        '2fa_code': 'Security code',
        '2fa_submit': 'Verify',
        '2fa_error': 'Incorrect code. Try again.',
        'admin_panel': 'Admin Panel',
        'current_user': 'Current user:',
        'role': 'role',
        'status': 'Status',
        'actions': 'Actions',
        'approved': 'Approved',
        'pending': 'Pending',
        'approve': 'Approve',
        'delete': 'Delete',
        'reset_password': 'Reset password',
        'change_role': 'Change role',
        'new_role': 'New role',
        'admin_mfa_code': 'MFA code (admin/root)',
        'role_changed': 'Role updated successfully',
        'mfa_required_role_change': 'You must enable 2FA to change roles',
        'mfa_invalid': 'Invalid MFA code',
        'cannot_change_own_role': 'You cannot change your own role',
        'cannot_change_root_without_root': 'Only a root user can change the role of another root',
        'cannot_remove_last_root': 'You cannot remove the last root user'
    }
}

def get_text(key):
    lang = session.get('lang', 'es')
    return texts[lang][key]

@app.route('/setlang/<lang>')
def setlang(lang):
    session['lang'] = lang
    return redirect(request.referrer or url_for('login'))

# Debes crear la tabla de alertas en la base de datos:
# CREATE TABLE IF NOT EXISTS alerts (
#   id INTEGER PRIMARY KEY AUTOINCREMENT,
#   user_id INTEGER,
#   type TEXT,
#   message TEXT,
#   timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
# );

# Registrar alerta

def log_alert(user_id, type_, message):
    conn = get_db_connection()
    conn.execute('INSERT INTO alerts (user_id, type, message) VALUES (?, ?, ?)', (user_id, type_, message))
    conn.commit()
    conn.close()

# Intentos fallidos de login
FAILED_LOGINS = {}
MAX_FAILED = 5

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    show_2fa = False
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        code = request.form.get('otp')
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        role_name = None
        if user:
            role = conn.execute('SELECT name FROM roles WHERE id = ?', (user['role_id'],)).fetchone()
            role_name = role['name'] if role else None
        conn.close()
        from datetime import datetime
        hora = datetime.now().hour
        if user and (hora < ALLOWED_HOURS[0] or hora > ALLOWED_HOURS[1]):
            log_alert(user['id'], 'acceso_fuera_horario', f"Intento de acceso fuera de horario: {hora}h")
        if user and check_password(password, user['password_hash']):
            if not user['approved']:
                return redirect(url_for('pending'))
            # Bypass MFA para admin y root (solo contraseña suficiente)
            if role_name in ('admin', 'root'):
                session['user_id'] = user['id']
                session['role'] = role_name
                session['session_version'] = safe_row_value(user, 'session_version', 0)
                if safe_row_value(user, 'must_change_password', 0):
                    return redirect(url_for('force_change_password'))
                return redirect('/admin/dashboard')
            # Para usuarios normales, si tienen 2FA configurado, pedir/verificar
            if user['otp_secret']:
                totp = pyotp.TOTP(user['otp_secret'])
                if not code:
                    show_2fa = True
                    msg = ''
                elif totp.verify(code):
                    session['user_id'] = user['id']
                    session['role'] = role_name
                    session['session_version'] = safe_row_value(user, 'session_version', 0)
                    if safe_row_value(user, 'must_change_password', 0):
                        return redirect(url_for('force_change_password'))
                    return redirect('/dashboard')
                else:
                    msg = get_text('2fa_error')
            else:
                # Acceso sin 2FA en usuarios estándar
                session['user_id'] = user['id']
                session['role'] = role_name
                session['session_version'] = safe_row_value(user, 'session_version', 0)
                if safe_row_value(user, 'must_change_password', 0):
                    return redirect(url_for('force_change_password'))
                return redirect('/dashboard')
        else:
            msg = get_text('incorrect')
    return render_template('login.html', show_2fa=show_2fa, msg=msg)

def generar_password_segura(longitud=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(random.choice(chars) for _ in range(longitud))
        # Validar requisitos
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in string.punctuation for c in password)):
            return password

@app.route('/sugerir_password')
def sugerir_password():
    return jsonify({'password': generar_password_segura()})

# Diccionario de traducción de roles
ROLE_TRANSLATIONS = {
    'es': {
        'HR Manager': 'Gerente de Recursos Humanos',
        'Recruitment Specialist': 'Especialista en Reclutamiento y Selección',
        'Payroll Analyst': 'Analista de Nómina',
        'Training and Development Coordinator': 'Coordinador de Capacitación y Desarrollo',
        'Labor Relations Specialist': 'Especialista en Relaciones Laborales',
        'Chief Financial Officer (CFO)': 'Director Financiero (CFO)',
        'Accountant': 'Contador',
        'Financial Analyst': 'Analista Financiero',
        'Treasurer': 'Tesorero',
        'Internal Auditor': 'Auditor Interno',
        'Chief Technology Officer (CTO)': 'Director de Tecnología (CTO)',
        'Systems Administrator': 'Administrador de Sistemas',
        'Software Developer': 'Desarrollador de Software',
        'Information Security Analyst': 'Analista de Seguridad Informática',
        'Technical Support': 'Soporte Técnico',
        'Administrative Manager': 'Gerente Administrativo',
        'Administrative Assistant': 'Asistente Administrativo',
        'Office Coordinator': 'Coordinador de Oficina',
        'Receptionist': 'Recepcionista',
        'Process Analyst': 'Analista de Procesos',
        'Operations Manager': 'Gerente de Operaciones',
        'Production Supervisor': 'Supervisor de Producción',
        'Logistics Coordinator': 'Coordinador de Logística',
        'Supply Chain Analyst': 'Analista de Cadena de Suministro',
        'Maintenance Technician': 'Técnico de Mantenimiento',
        'Sales Manager': 'Gerente de Ventas',
        'Account Executive': 'Ejecutivo de Cuentas',
        'Digital Marketing Specialist': 'Especialista en Marketing Digital',
        'Market Analyst': 'Analista de Mercado',
        'Advertising Coordinator': 'Coordinador de Publicidad',
        'Customer Service Manager': 'Gerente de Servicio al Cliente',
        'Customer Service Representative': 'Representante de Atención al Cliente',
        'After-Sales Support Specialist': 'Especialista en Soporte Postventa',
        'Customer Experience Coordinator': 'Coordinador de Experiencia del Cliente',
        'R&D Engineer': 'Ingeniero de I+D',
        'Product Researcher': 'Investigador de Producto',
        'Innovation Analyst': 'Analista de Innovación',
        'Corporate Lawyer': 'Abogado Corporativo',
        'Compliance Specialist': 'Especialista en Cumplimiento Normativo',
        'Legal Advisor': 'Asesor Legal',
        'Chief Executive Officer (CEO)': 'Director Ejecutivo (CEO)',
        'Chief Operating Officer (COO)': 'Director de Operaciones (COO)',
        'General Director': 'Director General',
        'General Manager': 'Gerente General'
    },
    'en': {}  # No translation needed for English
}

def get_role_options():
    conn = get_db_connection()
    roles = conn.execute('SELECT id, name FROM roles ORDER BY name').fetchall()
    conn.close()
    return roles

def get_role_name(role_id, lang='es'):
    conn = get_db_connection()
    role = conn.execute('SELECT name FROM roles WHERE id = ?', (role_id,)).fetchone()
    conn.close()
    if not role:
        return ''
    name = role['name']
    if lang == 'es' and name in ROLE_TRANSLATIONS['es']:
        return ROLE_TRANSLATIONS['es'][name]
    return name

@app.route('/register', methods=['GET', 'POST'])
def register():
    from flask import flash
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if (len(password) < 16 or
            not any(c.islower() for c in password) or
            not any(c.isupper() for c in password) or
            not any(c.isdigit() for c in password) or
            not any(c in string.punctuation for c in password)):
            flash(get_text('password_requirements'), 'error')
        else:
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if user:
                flash(get_text('user_exists'), 'error')
            else:
                session['pending_user'] = {'username': username, 'password': password}
                conn.close()
                return redirect(url_for('register_personal'))
            conn.close()
    return render_template('register.html')

# --- WebAuthn UI routes ---
@app.route('/webauthn/register', methods=['GET'])
def webauthn_register_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('webauthn_register.html')

@app.route('/webauthn/login', methods=['GET'])
def webauthn_login_page():
    return render_template('webauthn_login.html')

@app.route('/register/personal', methods=['GET', 'POST'])
def register_personal():
    if 'pending_user' not in session or not session['pending_user'].get('username'):
        flash('Debes completar el primer paso del registro.', 'error')
        return redirect(url_for('register'))
    msg = ''
    if request.method == 'POST':
        nombres = request.form.get('nombres', '').strip()
        apellido_paterno = request.form.get('apellido_paterno', '').strip()
        apellido_materno = request.form.get('apellido_materno', '').strip()
        fecha_nacimiento = request.form.get('fecha_nacimiento', '').strip()
        if not (nombres and apellido_paterno and apellido_materno and fecha_nacimiento):
            msg = 'Todos los campos son obligatorios.'
            return render_template('register_personal.html', msg=msg, nombres=nombres, apellido_paterno=apellido_paterno, apellido_materno=apellido_materno, fecha_nacimiento=fecha_nacimiento)
        # Validar año de nacimiento >= 1908
        try:
            year = int(fecha_nacimiento[:4])
            if year < 1908:
                msg = 'El año de nacimiento no puede ser anterior a 1908.'
                return render_template('register_personal.html', msg=msg, nombres=nombres, apellido_paterno=apellido_paterno, apellido_materno=apellido_materno, fecha_nacimiento=fecha_nacimiento)
        except Exception:
            msg = 'Fecha de nacimiento inválida.'
            return render_template('register_personal.html', msg=msg, nombres=nombres, apellido_paterno=apellido_paterno, apellido_materno=apellido_materno, fecha_nacimiento=fecha_nacimiento)
        # Buscar el id del rol 'user' en la base de datos
        conn = get_db_connection()
        user_role = conn.execute("SELECT id FROM roles WHERE name = 'user'").fetchone()
        role_id = user_role['id'] if user_role else 1  # fallback a 1 si no existe
        conn.close()
        # Limpiar cualquier clave 'role' y asegurar que 'role_id' es entero
        pending = session['pending_user']
        if 'role' in pending:
            pending.pop('role')
        pending['nombres'] = nombres
        pending['apellido_paterno'] = apellido_paterno
        pending['apellido_materno'] = apellido_materno
        pending['fecha_nacimiento'] = fecha_nacimiento
        pending['role_id'] = int(role_id)
        session['pending_user'] = pending
        return redirect(url_for('register_2fa'))
    return render_template('register_personal.html')

@app.route('/register/2fa', methods=['GET', 'POST'])
def register_2fa():
    print('DEBUG: Entrando a register_2fa')
    print('DEBUG: session:', dict(session))
    # Si por error existe 'role' en vez de 'role_id', lo corregimos aquí
    if 'pending_user' in session and 'role' in session['pending_user'] and 'role_id' not in session['pending_user']:
        session['pending_user']['role_id'] = session['pending_user'].pop('role')
    if 'pending_user' not in session or 'role_id' not in session['pending_user']:
        print('DEBUG: No hay pending_user o role_id en session, redirigiendo a /register')
        return redirect(url_for('register'))
    user = session['pending_user']
    # Mantener el mismo secreto QR en la sesión
    otp_secret = user.get('otp_secret')
    if not otp_secret:
        otp_secret = pyotp.random_base32()
        user['otp_secret'] = otp_secret
        session['pending_user'] = user
    totp = pyotp.TOTP(otp_secret)
    msg = ''
    if request.method == 'POST':
        code = request.form['code']
        # Tolerancia de 1 intervalo (30s antes o después)
        if totp.verify(code, valid_window=1):
            conn = get_db_connection()
            hashed = hash_password(user['password'])
            conn.execute('''INSERT INTO users (username, password_hash, role_id, otp_secret, created_at, approved) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 0)''',
                (user['username'], hashed, user['role_id'], otp_secret))
            conn.commit()
            conn.close()
            session.pop('pending_user', None)
            flash('Usuario registrado con éxito. Espera la aprobación de un administrador.', 'success')
            return redirect(url_for('login'))
        else:
            msg = 'Código incorrecto. Intenta de nuevo.'
    # Solo genera el QR una vez por sesión
    otp_uri = totp.provisioning_uri(name=user['username'], issuer_name="SGI App")
    if 'qr_b64' not in user:
        img = qrcode.make(otp_uri)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        user['qr_b64'] = qr_b64
        session['pending_user'] = user
    else:
        qr_b64 = user['qr_b64']
    # Estructura para Yubikey (solo placeholder, integración real requiere más código y frontend)
    yubikey_supported = True
    return render_template('register_2fa.html', qr_b64=qr_b64, msg=msg, yubikey_supported=yubikey_supported)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    role_name = get_role_name(user['role_id'], session.get('lang', 'es'))
    role = conn.execute('SELECT name FROM roles WHERE id = ?', (user['role_id'],)).fetchone()
    is_admin_user = role and role['name'] in ADMIN_ROLES
    conn.close()
    if is_admin_user:
        log_audit(user['id'], 'Acceso privilegiado', f'Rol: {role_name}')
    return render_template('dashboard.html', user=user, role_name=role_name, is_admin_user=is_admin_user)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# Helper para verificar si el usuario es admin o superior
ADMIN_ROLES = [
    'root',
    'admin',
    'Chief Executive Officer (CEO)',
    'Chief Operating Officer (COO)',
    'General Director',
    'General Manager',
    'Chief Technology Officer (CTO)',
    'Chief Financial Officer (CFO)'
]

def is_admin(user):
    conn = get_db_connection()
    role = conn.execute('SELECT name FROM roles WHERE id = ?', (user['role_id'],)).fetchone()
    conn.close()
    return role and role['name'] in ADMIN_ROLES

# Zero Trust: Decorador para validar sesión y permisos en rutas sensibles
from functools import wraps

def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        # Validar invalidación de sesión por cambios críticos
        try:
            conn = get_db_connection()
            row = conn.execute('SELECT session_version FROM users WHERE id=?', (session['user_id'],)).fetchone()
            conn.close()
            if row and session.get('session_version') is not None and row['session_version'] != session.get('session_version'):
                session.clear()
                flash('Sesión invalidada. Inicia sesión nuevamente.', 'warning')
                return redirect(url_for('login'))
        except Exception:
            pass
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        if not is_admin(user):
            return redirect(url_for('access_denied'))
        return f(*args, **kwargs)
    return decorated

# --- Ruta para ver y administrar usuarios (admin_users) ---
@app.route('/admin/users')
@require_admin
def admin_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    role = conn.execute('SELECT name FROM roles WHERE id = ?', (user['role_id'],)).fetchone()
    users = conn.execute('SELECT * FROM users').fetchall()
    roles = {r['id']: r['name'] for r in conn.execute('SELECT * FROM roles').fetchall()}
    conn.close()
    return render_template('admin_dashboard_simple.html', users=users, roles=roles, current_user=user, current_role=role['name'], get_text=get_text)

# --- Ruta para ver y administrar roles (admin_roles) ---
@app.route('/admin/roles')
@require_admin
def admin_roles():
    conn = get_db_connection()
    roles = conn.execute('SELECT * FROM roles').fetchall()
    conn.close()
    return render_template('admin_roles.html', roles=roles)

# --- Ruta para el dashboard de administración ---
@app.route('/admin/dashboard')
@require_admin
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    role = conn.execute('SELECT name FROM roles WHERE id = ?', (user['role_id'],)).fetchone()
    users = conn.execute('SELECT * FROM users').fetchall()
    roles = {r['id']: r['name'] for r in conn.execute('SELECT * FROM roles').fetchall()}
    conn.close()
    return render_template('admin_dashboard_simple.html', users=users, roles=roles, current_user=user, current_role=role['name'], get_text=get_text)

@app.route('/admin/users/approve/<int:user_id>')
def admin_approve_user(user_id):
    if 'user_id' not in session:
        return redirect('/')
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not is_admin(admin):
        conn.close()
        return redirect(url_for('access_denied'))
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user and user['approved'] == 0 and user['id'] != admin['id']:
        conn.execute('UPDATE users SET approved = 1 WHERE id = ?', (user_id,))
        conn.commit()
        log_audit(admin['id'], 'Aprobación usuario', user['username'])
    conn.close()
    return redirect(url_for('admin_users'))

@app.route('/admin/users/block/<int:user_id>')
@require_admin
def block_user(user_id):
    conn = get_db_connection()
    conn.execute('UPDATE users SET approved=0 WHERE id=?', (user_id,))
    conn.commit()
    conn.close()
    flash('Usuario bloqueado', 'warning')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<int:user_id>')
@require_admin
def delete_user(user_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id=?', (user_id,))
    conn.commit()
    conn.close()
    flash('Usuario eliminado', 'danger')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/reset_password/<int:user_id>')
@require_admin
def admin_reset_password(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not user:
        conn.close()
        flash('Usuario no encontrado', 'danger')
        return redirect(url_for('admin_users'))
    # Generar password temporal seguro
    temp_pass = generar_password_segura(20)
    hashed = hash_password(temp_pass)
    conn.execute('UPDATE users SET password_hash=?, must_change_password=1 WHERE id=?', (hashed, user_id))
    conn.commit()
    conn.close()
    flash(f'Password reseteado. Nueva contraseña temporal: {temp_pass}', 'success')
    log_audit(session['user_id'], 'Reset password', user['username'])
    return redirect(url_for('admin_users'))

@app.route('/admin/users/change_role/<int:user_id>', methods=['GET', 'POST'])
@require_admin
def change_user_role(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    admin_user = conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    target_user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    roles = conn.execute('SELECT * FROM roles ORDER BY name').fetchall()
    # Obtener nombres de roles actuales
    def role_name_from_id(rid):
        row = conn.execute('SELECT name FROM roles WHERE id=?', (rid,)).fetchone()
        return row['name'] if row else ''
    if not target_user:
        conn.close()
        flash('Usuario no encontrado', 'danger')
        return redirect(url_for('admin_users'))
    admin_role_name = role_name_from_id(admin_user['role_id'])
    target_role_name = role_name_from_id(target_user['role_id'])
    # No permitir cambiar propio rol (por seguridad)
    if target_user['id'] == admin_user['id'] and request.method == 'POST':
        conn.close()
        flash(get_text('cannot_change_own_role'), 'danger')
        return redirect(url_for('admin_users'))
    # Solo root puede cambiar rol de un root distinto
    if target_role_name == 'root' and admin_role_name != 'root':
        conn.close()
        flash(get_text('cannot_change_root_without_root'), 'danger')
        return redirect(url_for('admin_users'))
    if request.method == 'POST':
        new_role_id = request.form.get('new_role_id')
        mfa_code = request.form.get('mfa_code')
        # Verificar que admin tenga 2FA
        if not admin_user['otp_secret']:
            conn.close()
            flash(get_text('mfa_required_role_change'), 'danger')
            return redirect(url_for('admin_users'))
        totp = pyotp.TOTP(admin_user['otp_secret'])
        if not mfa_code or not totp.verify(mfa_code, valid_window=1):
            conn.close()
            flash(get_text('mfa_invalid'), 'danger')
            return redirect(url_for('change_user_role', user_id=user_id))
        # Validar rol objetivo existe
        role_exists = conn.execute('SELECT id, name FROM roles WHERE id=?', (new_role_id,)).fetchone()
        if not role_exists:
            conn.close()
            flash('Rol inválido', 'danger')
            return redirect(url_for('change_user_role', user_id=user_id))
        new_role_name = role_exists['name']
        # Protección: evitar eliminar último root
        if target_role_name == 'root' and new_role_name != 'root':
            root_count = conn.execute('SELECT COUNT(*) as c FROM users u JOIN roles r ON u.role_id = r.id WHERE r.name = "root"').fetchone()['c']
            if root_count <= 1:
                conn.close()
                flash(get_text('cannot_remove_last_root'), 'danger')
                return redirect(url_for('admin_users'))
        conn.execute('UPDATE users SET role_id=?, session_version = COALESCE(session_version,0)+1 WHERE id=?', (new_role_id, user_id))
        conn.commit()
        log_audit(admin_user['id'], 'Cambio rol', f"{target_user['username']}: {target_role_name} -> {new_role_name}")
        conn.close()
        flash(get_text('role_changed'), 'success')
        return redirect(url_for('admin_users'))
    # GET -> mostrar formulario
    admin_has_mfa = bool(admin_user['otp_secret'])
    conn.close()
    return render_template('admin_change_role.html', target_user=target_user, roles=roles, target_role_name=target_role_name, admin_has_mfa=admin_has_mfa, get_text=get_text)

@app.route('/admin/roles/edit/<int:role_id>', methods=['GET', 'POST'])
@require_admin
def edit_role(role_id):
    conn = get_db_connection()
    role = conn.execute('SELECT * FROM roles WHERE id=?', (role_id,)).fetchone()
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        conn.execute('UPDATE roles SET name=?, description=? WHERE id=?', (name, description, role_id))
        conn.commit()
        conn.close()
        flash('Rol actualizado', 'success')
        return redirect(url_for('admin_roles'))
    conn.close()
    return render_template('admin_roles.html', roles=[role])

@app.route('/admin/roles/delete/<int:role_id>')
@require_admin
def delete_role(role_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM roles WHERE id=?', (role_id,))
    conn.commit()
    conn.close()
    flash('Rol eliminado', 'danger')
    return redirect(url_for('admin_roles'))

@app.route('/profile/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    old = request.form.get('old_password')
    new = request.form.get('new_password')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not check_password(old, user['password_hash']):
        flash('Contraseña actual incorrecta', 'danger')
        conn.close()
        return redirect(url_for('profile'))
    if len(new) < 16 or not any(c.islower() for c in new) or not any(c.isupper() for c in new) or not any(c.isdigit() for c in new) or not any(c in string.punctuation for c in new):
        flash('La nueva contraseña no cumple requisitos', 'danger')
        conn.close()
        return redirect(url_for('profile'))
    hashed = hash_password(new)
    conn.execute('UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?', (hashed, user['id']))
    conn.commit()
    conn.close()
    flash('Contraseña cambiada', 'success')
    return redirect(url_for('profile'))

@app.route('/force_change_password', methods=['GET','POST'])
def force_change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    conn.close()
    if not user or not user['must_change_password']:
        return redirect(url_for('dashboard'))
    msg = ''
    if request.method == 'POST':
        old = request.form.get('old_password')
        new = request.form.get('new_password')
        if not check_password(old, user['password_hash']):
            msg = 'Contraseña temporal incorrecta'
        elif (len(new) < 16 or not any(c.islower() for c in new) or not any(c.isupper() for c in new) or not any(c.isdigit() for c in new) or not any(c in string.punctuation for c in new)):
            msg = 'La nueva contraseña no cumple requisitos'
        else:
            c2 = get_db_connection()
            c2.execute('UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?', (hash_password(new), user['id']))
            c2.commit(); c2.close()
            flash('Contraseña actualizada. Continúa.', 'success')
            return redirect(url_for('dashboard'))
    return render_template('force_change_password.html', msg=msg)

@app.route('/profile/toggle_2fa', methods=['POST'])
def toggle_2fa():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if user['otp_secret']:
        # Desactivar 2FA
        conn.execute('UPDATE users SET otp_secret=NULL WHERE id=?', (user['id'],))
        flash('2FA desactivado', 'warning')
    else:
        # Activar 2FA
        import pyotp
        otp_secret = pyotp.random_base32()
        conn.execute('UPDATE users SET otp_secret=? WHERE id=?', (otp_secret, user['id']))
        flash('2FA activado. Vuelve a iniciar sesión para configurar.', 'success')
    conn.commit()
    conn.close()
    return redirect(url_for('profile'))

# Helper para roles temporales
TEMP_ROLE_DURATION_MINUTES = 15

def set_temp_admin(user_id):
    expires = (datetime.datetime.utcnow() + datetime.timedelta(minutes=TEMP_ROLE_DURATION_MINUTES)).isoformat()
    session['temp_admin'] = {'user_id': user_id, 'expires': expires}
    log_audit(user_id, 'Elevación temporal de privilegios', f'Expira: {expires}')

def is_temp_admin():
    temp = session.get('temp_admin')
    if not temp:
        return False
    expires = datetime.datetime.fromisoformat(temp['expires'])
    if datetime.datetime.utcnow() > expires:
        session.pop('temp_admin')
        return False
    return session.get('user_id') == temp['user_id']

@app.route('/admin/elevate')
@require_admin
def elevate_admin():
    if 'user_id' not in session:
        return redirect('/')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    role = conn.execute('SELECT name FROM roles WHERE id = ?', (user['role_id'],)).fetchone()
    conn.close()
    if role and role['name'] in ADMIN_ROLES:
        set_temp_admin(user['id'])
        return 'Privilegios elevados temporalmente. <a href="/dashboard">Volver</a>'
    return redirect(url_for('access_denied'))

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed):
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False

# Vista de alertas para admin/root
@app.route('/admin/alerts')
@require_admin
def view_alerts():
    if 'user_id' not in session:
        return redirect('/')
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not is_admin(admin):
        conn.close()
        return redirect(url_for('access_denied'))
    alerts = conn.execute('SELECT a.id, a.user_id, a.type, a.message, a.timestamp, u.username FROM alerts a LEFT JOIN users u ON a.user_id = u.id ORDER BY a.timestamp DESC').fetchall()
    conn.close()
    return render_template_string('''
        <h2>Alertas de seguridad</h2>
        <table border=1>
            <tr><th>ID</th><th>Usuario</th><th>Tipo</th><th>Mensaje</th><th>Fecha</th></tr>
            {% for a in alerts %}
            <tr>
                <td>{{a['id']}}</td>
                <td>{{a['username']}}</td>
                <td>{{a['type']}}</td>
                <td>{{a['message']}}</td>
                <td>{{a['timestamp']}}</td>
            </tr>
            {% endfor %}
        </table>
        <a href="{{ url_for('dashboard') }}">Volver</a>
    ''', alerts=alerts)

@app.route('/pending')
def pending():
    return render_template('pending.html')

@app.route('/access_denied')
def access_denied():
    return render_template('access_denied.html'), 403

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    webauthn_creds = conn.execute('SELECT * FROM webauthn_credentials WHERE user_id = ?', (session['user_id'],)).fetchall()
    role_name = get_role_name(user['role_id'], session.get('lang', 'es'))
    if request.method == 'POST':
        nombres = request.form.get('nombres')
        apellido_paterno = request.form.get('apellido_paterno')
        apellido_materno = request.form.get('apellido_materno')
        fecha_nacimiento = request.form.get('fecha_nacimiento')
        conn.execute('UPDATE users SET nombres=?, apellido_paterno=?, apellido_materno=?, fecha_nacimiento=? WHERE id=?',
            (nombres, apellido_paterno, apellido_materno, fecha_nacimiento, user['id']))
        conn.commit()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        webauthn_creds = conn.execute('SELECT * FROM webauthn_credentials WHERE user_id = ?', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('profile.html', user=user, role_name=role_name, webauthn_creds=webauthn_creds)

# --- WebAuthn API Routes ---
@app.route('/webauthn/register/begin', methods=['POST'])
def webauthn_register_begin():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    
    # Obtener credenciales existentes del usuario para evitar duplicados
    rows = conn.execute('SELECT credential_id FROM webauthn_credentials WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    existing = []
    for r in rows:
        try:
            existing.append(
                PublicKeyCredentialDescriptor(id=websafe_decode(r['credential_id']), type='public-key')
            )
        except Exception:
            pass

    # Construir entidad de usuario
    user_entity = PublicKeyCredentialUserEntity(
        id=str(user_id).encode('utf-8'),
        name=user['username'],
        display_name=user['nombres'] if user['nombres'] else user['username']
    )

    try:
        creation_options, state = fido2_server.register_begin(
            user_entity,
            credentials=existing,
            user_verification='preferred'
        )
    except Exception as e:
        print(f"Error in register_begin: {e}")
        return jsonify({'error': 'WebAuthn registration failed'}), 500

    session['webauthn_state'] = state

    # Serializar opciones en formato similar al anterior (listas de ints)
    def to_list(b: bytes):
        return list(b) if isinstance(b, (bytes, bytearray)) else b

    exclude_serialized = []
    if creation_options.exclude_credentials:
        for cred in creation_options.exclude_credentials:
            exclude_serialized.append({
                'type': cred.type,
                'id': to_list(cred.id)
            })

    registration_dict = {
        'challenge': to_list(creation_options.challenge),
        'rp': {
            'id': creation_options.rp.id,
            'name': creation_options.rp.name
        },
        'user': {
            'id': to_list(creation_options.user.id),
            'name': creation_options.user.name,
            'displayName': creation_options.user.display_name
        },
        'pubKeyCredParams': [
            {'type': p.type, 'alg': p.alg} for p in creation_options.pub_key_cred_params
        ],
        'timeout': creation_options.timeout or 60000,
        'attestation': creation_options.attestation or 'none',
        'excludeCredentials': exclude_serialized,
        'authenticatorSelection': {
            'authenticatorAttachment': 'cross-platform',
            'userVerification': 'preferred',
            'requireResidentKey': False
        }
    }
    print(f"Sending registration data: {registration_dict}")
    return jsonify(registration_dict)

@app.route('/webauthn/register/complete', methods=['POST'])
def webauthn_register_complete():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if 'webauthn_state' not in session:
        return jsonify({'error': 'No registration in progress'}), 400
    
    user_id = session['user_id']
    state = session.pop('webauthn_state')
    
    try:
        data = request.get_json(force=True)
        # Cliente envía arrays de ints; convertir a bytes
        client_data = bytes(data['clientDataJSON'])
        attestation_object = bytes(data['attestationObject'])

        client_data_obj = CollectedClientData(client_data)
        att_obj = AttestationObject(attestation_object)

        auth_data = fido2_server.register_complete(state, client_data_obj, att_obj)

        credential_id = websafe_encode(auth_data.credential_id)
        public_key_cose = websafe_encode(auth_data.credential_public_key)
        sign_count = auth_data.sign_count

        conn = get_db_connection()
        conn.execute(
            'INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)',
            (user_id, credential_id, public_key_cose, sign_count)
        )
        conn.commit()
        conn.close()
        return jsonify({'status': 'ok'})
    except Exception as e:
        print(f"WebAuthn registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 400

@app.route('/webauthn/login/begin', methods=['POST'])
def webauthn_login_begin():
    try:
        conn = get_db_connection()
        username = request.json.get('username') if request.is_json else None
        allow_list = []
        target_user_id = None
        if username:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if not user:
                conn.close()
                return jsonify({'error': 'User not found'}), 404
            target_user_id = user['id']
            rows = conn.execute('SELECT credential_id FROM webauthn_credentials WHERE user_id = ?', (user['id'],)).fetchall()
            for r in rows:
                try:
                    allow_list.append(
                        PublicKeyCredentialDescriptor(id=websafe_decode(r['credential_id']), type='public-key')
                    )
                except Exception:
                    pass
        conn.close()

        assertion_options, state = fido2_server.authenticate_begin(
            credentials=allow_list,
            user_verification='preferred'
        )
        session['webauthn_auth_state'] = {'state': state, 'user_id': target_user_id}

        def to_list(b: bytes):
            return list(b) if isinstance(b, (bytes, bytearray)) else b

        allow_serialized = []
        if assertion_options.allow_credentials:
            for cred in assertion_options.allow_credentials:
                allow_serialized.append({'type': cred.type, 'id': to_list(cred.id)})

        auth_dict = {
            'challenge': to_list(assertion_options.challenge),
            'timeout': assertion_options.timeout,
            'rpId': assertion_options.rp_id,
            'allowCredentials': allow_serialized,
            'userVerification': assertion_options.user_verification or 'preferred'
        }
        return jsonify(auth_dict)
        
    except Exception as e:
        print(f"WebAuthn login begin error: {e}")
        return jsonify({'error': 'Authentication failed'}), 400

@app.route('/webauthn/login/complete', methods=['POST'])
def webauthn_login_complete():
    if 'webauthn_auth_state' not in session:
        return jsonify({'error': 'No authentication in progress'}), 400
    state_obj = session.pop('webauthn_auth_state')
    state = state_obj['state']
    try:
        data = request.get_json(force=True)
        credential_id_bytes = bytes(data['id'])  # array of ints
        client_data = CollectedClientData(bytes(data['clientDataJSON']))
        authenticator_data = bytes(data['authenticatorData'])
        signature = bytes(data['signature'])
        user_handle = bytes(data['userHandle']) if data.get('userHandle') else None
        # Buscar credencial por credential_id (websafe codificado)
        from fido2.utils import websafe_encode as _enc
        lookup_id = _enc(credential_id_bytes)
        conn = get_db_connection()
        cred_row = conn.execute('SELECT * FROM webauthn_credentials WHERE credential_id = ?', (lookup_id,)).fetchone()
        if not cred_row:
            conn.close(); return jsonify({'error': 'Credential not found'}), 404
        user = conn.execute('SELECT * FROM users WHERE id = ?', (cred_row['user_id'],)).fetchone()
        if not user:
            conn.close(); return jsonify({'error': 'User not found'}), 404

        descriptor = PublicKeyCredentialDescriptor(id=websafe_decode(cred_row['credential_id']), type='public-key')
        auth_data_obj = AuthenticatorData(authenticator_data)

        result = fido2_server.authenticate_complete(
            state,
            [descriptor],
            credential_id_bytes,
            client_data,
            auth_data_obj,
            signature
        )
        # Detección básica de replay: sign_count no incrementa
        try:
            prev = cred_row['sign_count'] if cred_row['sign_count'] is not None else 0
            newc = getattr(auth_data_obj, 'sign_count', None)
            if newc is not None and newc != 0:
                if newc <= prev:
                    log_alert(user['id'], 'webauthn_replay_suspect', f'cred {cred_row["id"]} new={newc} prev={prev}')
                else:
                    conn.execute('UPDATE webauthn_credentials SET sign_count=? WHERE id=?', (newc, cred_row['id']))
                    conn.commit()
        except Exception:
            pass
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = get_role_name(user['role_id'])
        try:
            session['session_version'] = conn.execute('SELECT session_version FROM users WHERE id=?', (user['id'],)).fetchone()['session_version']
        except Exception:
            pass
        conn.close()
        return jsonify({'status': 'ok', 'redirect': '/dashboard'})
    except Exception as e:
        print(f"WebAuthn login complete error: {e}")
        return jsonify({'error': 'Authentication failed'}), 400

if __name__ == '__main__':
    import os
    # Get environment variables for Docker deployment
    debug_mode = os.getenv('FLASK_ENV', 'production') != 'production'
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 5000))
    
    app.run(host=host, port=port, debug=debug_mode)