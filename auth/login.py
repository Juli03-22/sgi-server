from flask import request, redirect, url_for, session, flash
from .models import User
import sqlite3
from config import Config

def login_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(Config.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user and user[2] == password:  # Assuming password is in the third column
            session['user_id'] = user[0]  # Assuming id is in the first column
            session['username'] = user[1]  # Assuming username is in the second column
            session['role'] = user[3]      # Assuming role is in the fourth column
            
            if user[3] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user[3] == 'root':
                return redirect(url_for('root_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password')
    
    return redirect(url_for('login'))