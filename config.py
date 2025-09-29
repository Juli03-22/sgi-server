import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'tu_clave_secreta')
    DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'db.sqlite3')
    ALLOWED_HOURS = (7, 22)
    # Agrega aquí otras configuraciones globales
