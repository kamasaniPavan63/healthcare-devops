import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'hcs-super-secret-key-2024-hybrid-crypto')

    # ✅ FIXED DATABASE CONFIG
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'healthcare.db') + '?timeout=30'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ✅ Better SQLite handling
    SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {"check_same_thread": False}
    }

    JWT_EXPIRATION = timedelta(hours=8)
    ADMIN_SECRET_KEY = os.environ.get('ADMIN_SECRET_KEY', 'ADMIN-MASTER-KEY-2024')

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload

    DEBUG = True