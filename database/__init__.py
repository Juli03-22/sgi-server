# Tabla para credenciales WebAuthn/FIDO2
def create_webauthn_table(conn):
	conn.execute('''
		CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			credential_id TEXT NOT NULL,
			public_key TEXT NOT NULL,
			sign_count INTEGER DEFAULT 0,
			transports TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)
	''')

def migrate():
	conn = get_db_connection()
	create_webauthn_table(conn)
	conn.commit()
	conn.close()
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()