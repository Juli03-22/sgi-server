from flask import Flask, render_template, render_template_string, request, redirect, session, url_for, jsonify, flash
import sqlite3
import os
import random
import string
import pyotp
import qrcode
import io
import base64
import hashlib
import datetime
import bcrypt
from functools import wraps

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta'


def get_db_connection():
    DB_PATH = r'C:\Users\Messy\OneDrive\Documentos\GitHub\sgi-server\web-app\src\database\db.sqlite3'
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Función para cifrar (hash) los logs de auditoría
SECRET_LOG_KEY = 'clave_secreta_audit'  # Cambia esto por una clave segura

def encrypt_log(text):
    # Simple hash+base64 para ejemplo, usa cifrado fuerte en producción
    h = hashlib.sha256((SECRET_LOG_KEY + text).encode()).digest()
    return base64.b64encode(h).decode()

# Modificar log_audit para guardar hash

def log_audit(user_id, action, details=None):
    raw = f"{user_id}|{action}|{details if details else ''}"
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
    '2fa_error': 'Código incorrecto. Intenta de nuevo.'
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
    '2fa_error': 'Incorrect code. Try again.'
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

ALLOWED_HOURS = (7, 22)  # Acceso permitido de 7:00 a 22:00

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
            elif user['otp_secret']:
                totp = pyotp.TOTP(user['otp_secret'])
                if not code:
                    show_2fa = True
                    msg = ''
                elif totp.verify(code):
                    session['user_id'] = user['id']
                    session['role'] = role_name
                    return redirect('/dashboard')
                else:
                    if role_name in ADMIN_ROLES:
                        msg = 'MFA obligatorio para cuentas privilegiadas. Acceso denegado.'
                    else:
                        msg = get_text('2fa_error')
            else:
                msg = 'Usuario sin 2FA. Contacte al administrador.'
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

@app.route('/register/personal', methods=['GET', 'POST'])
def register_personal():
    if 'pending_user' not in session:
        return redirect(url_for('register'))
    msg = ''
    roles = get_role_options()
    if request.method == 'POST':
        nombres = request.form['nombres']
        apellido_paterno = request.form['apellido_paterno']
        apellido_materno = request.form['apellido_materno']
        fecha_nacimiento = request.form['fecha_nacimiento']
        role_id = int(request.form['role_id'])
        session['pending_user'].update({
            'nombres': nombres,
            'apellido_paterno': apellido_paterno,
            'apellido_materno': apellido_materno,
            'fecha_nacimiento': fecha_nacimiento,
            'role_id': role_id
        })
        return redirect(url_for('register_2fa'))
    lang = session.get('lang', 'es')
    return render_template('register_personal.html', roles=roles, role_translate=lambda name: ROLE_TRANSLATIONS.get(lang, {}).get(name, name))

@app.route('/register/2fa', methods=['GET', 'POST'])
def register_2fa():
    if 'pending_user' not in session or 'role_id' not in session['pending_user']:
        return redirect(url_for('register'))
    user = session['pending_user']
    otp_secret = user.get('otp_secret')
    if not otp_secret:
        otp_secret = pyotp.random_base32()
        user['otp_secret'] = otp_secret
    totp = pyotp.TOTP(otp_secret)
    msg = ''
    if request.method == 'POST':
        code = request.form['code']
        if totp.verify(code):
            conn = get_db_connection()
            hashed = hash_password(user['password'])
            conn.execute('''INSERT INTO users (username, password_hash, role_id, otp_secret, created_at, approved) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 0)''',
                (user['username'], hashed, user['role_id'], otp_secret))
            conn.commit()
            conn.close()
            session.pop('pending_user', None)
            return redirect(url_for('login'))
        else:
            msg = get_text('2fa_error')
    otp_uri = totp.provisioning_uri(name=user['username'], issuer_name="SGI App")
    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    return render_template('register_2fa.html', qr_b64=qr_b64, msg=msg)

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
    conn.execute('UPDATE users SET password_hash=? WHERE id=?', (hashed, user['id']))
    conn.commit()
    conn.close()
    flash('Contraseña cambiada', 'success')
    return redirect(url_for('profile'))

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
    conn.close()
    return render_template('profile.html', user=user, role_name=role_name)

if __name__ == '__main__':
    app.run(debug=True)