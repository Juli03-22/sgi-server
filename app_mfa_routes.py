from flask import session, redirect, url_for, flash
from app import app, get_db_connection
import pyotp

@app.route('/profile/mfa/regenerate_2fa', methods=['POST'])
def regenerate_2fa():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    creds = conn.execute('SELECT * FROM webauthn_credentials WHERE user_id = ?', (user['id'],)).fetchall()
    if not user['otp_secret']:
        flash('No tienes 2FA por app configurado.', 'danger')
        conn.close()
        return redirect(url_for('profile'))
    if not creds:
        flash('Debes tener al menos un método de MFA activo.', 'danger')
        conn.close()
        return redirect(url_for('profile'))
    otp_secret = pyotp.random_base32()
    conn.execute('UPDATE users SET otp_secret=? WHERE id=?', (otp_secret, user['id']))
    conn.commit()
    conn.close()
    flash('Código 2FA regenerado. Configura tu app nuevamente.', 'success')
    return redirect(url_for('profile'))

@app.route('/profile/mfa/delete_2fa', methods=['POST'])
def delete_2fa():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    creds = conn.execute('SELECT * FROM webauthn_credentials WHERE user_id = ?', (user['id'],)).fetchall()
    if not user['otp_secret']:
        flash('No tienes 2FA por app configurado.', 'danger')
        conn.close()
        return redirect(url_for('profile'))
    if not creds:
        flash('Debes tener al menos un método de MFA activo.', 'danger')
        conn.close()
        return redirect(url_for('profile'))
    conn.execute('UPDATE users SET otp_secret=NULL WHERE id=?', (user['id'],))
    conn.commit()
    conn.close()
    flash('2FA por app eliminado.', 'warning')
    return redirect(url_for('profile'))

@app.route('/profile/mfa/delete_key/<int:key_id>', methods=['POST'])
def delete_webauthn_key(key_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    creds = conn.execute('SELECT * FROM webauthn_credentials WHERE user_id = ?', (session['user_id'],)).fetchall()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if len(creds) <= 1 and not user['otp_secret']:
        flash('Debes tener al menos un método de MFA activo.', 'danger')
        conn.close()
        return redirect(url_for('profile'))
    conn.execute('DELETE FROM webauthn_credentials WHERE id=? AND user_id=?', (key_id, session['user_id']))
    conn.commit()
    conn.close()
    flash('Llave física eliminada.', 'warning')
    return redirect(url_for('profile'))
