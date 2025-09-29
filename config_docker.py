import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Base configuration class"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DB_PATH = os.environ.get('DB_PATH') or str(BASE_DIR / 'database' / 'db.sqlite3')
    ALLOWED_HOURS = [6, 22]  # 6:00 AM to 10:00 PM
    
    # WebAuthn Configuration
    RP_ID = os.environ.get('RP_ID') or '127.0.0.1'
    RP_NAME = os.environ.get('RP_NAME') or 'SGI IAM'
    
    # Flask Configuration
    FLASK_HOST = os.environ.get('FLASK_HOST') or '127.0.0.1'
    FLASK_PORT = int(os.environ.get('FLASK_PORT', 5000))
    
class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    
class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    FLASK_HOST = '0.0.0.0'  # Listen on all interfaces in production

class DockerConfig(ProductionConfig):
    """Docker-specific configuration"""
    DB_PATH = '/app/database/db.sqlite3'
    RP_ID = 'localhost'  # Docker typically uses localhost

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'docker': DockerConfig,
    'default': DevelopmentConfig
}