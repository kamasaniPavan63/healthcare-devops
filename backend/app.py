"""
Hybrid Cryptographic Architecture for Healthcare Data Security in Cloud Environments
"""
import os
import sys

# Add backend directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from config import Config
from extensions import db


def create_app():
    app = Flask(
        __name__,
        static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend'),
        static_url_path=''
    )
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # ✅ FIX: Add /api prefix to all blueprints
    from routes.auth_routes import auth_bp
    from routes.admin_routes import admin_bp
    from routes.doctor_routes import doctor_bp
    from routes.patient_routes import patient_bp
    from routes.medical_routes import medical_bp

    app.register_blueprint(auth_bp, url_prefix="/api")
    app.register_blueprint(admin_bp, url_prefix="/api")
    app.register_blueprint(doctor_bp, url_prefix="/api")
    app.register_blueprint(patient_bp, url_prefix="/api")
    app.register_blueprint(medical_bp, url_prefix="/api")

    # Serve frontend pages (KEEP AS YOU WANTED)
    @app.route('/')
    def index():
        return send_from_directory(app.static_folder, 'login.html')

    @app.route('/<path:filename>')
    def serve_frontend(filename):
        return send_from_directory(app.static_folder, filename)

    # Health check
    @app.route('/api/health')
    def health():
        return jsonify({'status': 'ok', 'system': 'Healthcare Security Platform v1.0'})

    # Create database tables
    with app.app_context():
        db.create_all()
        _seed_admin()

    return app


def _seed_admin():
    """Create default admin account if none exists."""
    from models import User
    from crypto.ecdsa_module import generate_ecdsa_keypair, serialize_private_key, serialize_public_key
    from crypto.ecdh_module import generate_ecdh_keypair
    from crypto.ecdh_module import serialize_private_key as ecdh_priv_ser
    from crypto.ecdh_module import serialize_public_key as ecdh_pub_ser

    if User.query.filter_by(role='admin').first():
        return

    ecdsa_priv, ecdsa_pub = generate_ecdsa_keypair()
    ecdh_priv, ecdh_pub = generate_ecdh_keypair()

    admin = User(
        name='System Administrator',
        email='admin@healthcare.com',
        role='admin',
        status='active',
        ecdsa_public_key=serialize_public_key(ecdsa_pub),
        ecdsa_private_key=serialize_private_key(ecdsa_priv),
        ecdh_public_key=ecdh_pub_ser(ecdh_pub),
        ecdh_private_key=ecdh_priv_ser(ecdh_priv)
    )
    admin.set_password('Admin@1234')
    db.session.add(admin)
    db.session.commit()
    print('✓ Default admin created: admin@healthcare.com / Admin@1234')


app = create_app()

if __name__ == '__main__':
    print('=' * 60)
    print(' Healthcare Security Platform')
    print(' Hybrid Cryptographic Architecture')
    print('=' * 60)
    print(' URL: http://127.0.0.1:5000')
    print(' Default Admin: admin@healthcare.com / Admin@1234')
    print('=' * 60)

    app.run(
        debug=True,
        host='0.0.0.0',
        port=5000,
        use_reloader=False,
        threaded=False
    )