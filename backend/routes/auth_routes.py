"""
Authentication Routes: register, login, logout, profile.
"""

import jwt
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app
from extensions import db
from models import User, Patient, Doctor, ActivityLog
from datetime import datetime, timedelta, timezone

from crypto.ecdsa_module import generate_ecdsa_keypair
from crypto.ecdh_module import generate_ecdh_keypair

from crypto.ecdsa_module import serialize_private_key as ecdsa_priv_ser
from crypto.ecdsa_module import serialize_public_key as ecdsa_pub_ser
from crypto.ecdh_module import serialize_private_key as ecdh_priv_ser
from crypto.ecdh_module import serialize_public_key as ecdh_pub_ser

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


# ---------------- TOKEN GENERATION ---------------- #
def generate_token(user: User) -> str:
    payload = {
        'user_id': user.id,
        'role': user.role,
        'exp': datetime.utcnow() + timedelta(hours=8)
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')


# ---------------- ACTIVITY LOG ---------------- #
def log_activity(user_id: int, action: str, resource: str = None, resource_id: int = None):
    log = ActivityLog(
        user_id=user_id,
        action=action,
        resource=resource,
        resource_id=resource_id,
        ip_address=request.remote_addr,
        timestamp=datetime.now(timezone.utc)  # ✅ FIX HERE
    )


# ---------------- REGISTER ---------------- #
@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    required = ['name', 'email', 'password', 'role']
    if not all(k in data for k in required):
        return jsonify({'error': 'Missing required fields'}), 400

    role = data['role'].lower()

    # Validate role
    if role not in ['patient', 'doctor', 'admin']:
        return jsonify({'error': 'Invalid role'}), 400

    # Admin security check
    if role == 'admin':
        if data.get('admin_secret') != current_app.config['ADMIN_SECRET_KEY']:
            return jsonify({'error': 'Invalid admin secret key'}), 403

    # Check duplicate email
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 409

    # ---------------- FIXED STATUS LOGIC ---------------- #
    # Doctor → pending approval
    # Patient → active
    # Admin → active
    if role == 'doctor':
        status = 'pending'
    else:
        status = 'active'
    # --------------------------------------------------- #

    # Generate crypto keys
    ecdsa_priv, ecdsa_pub = generate_ecdsa_keypair()
    ecdh_priv, ecdh_pub = generate_ecdh_keypair()

    # Create user
    user = User(
        name=data['name'],
        email=data['email'],
        role=role,
        status=status,
        ecdsa_public_key=ecdsa_pub_ser(ecdsa_pub),
        ecdsa_private_key=ecdsa_priv_ser(ecdsa_priv),
        ecdh_public_key=ecdh_pub_ser(ecdh_pub),
        ecdh_private_key=ecdh_priv_ser(ecdh_priv)
    )

    user.set_password(data['password'])
    db.session.add(user)
    db.session.flush()

    # Create role-specific profiles
    if role == 'patient':
        patient = Patient(
            user_id=user.id,
            age=data.get('age'),
            gender=data.get('gender'),
            blood_group=data.get('blood_group'),
            medical_history=data.get('medical_history', '')
        )
        db.session.add(patient)

    elif role == 'doctor':
        doctor = Doctor(
            user_id=user.id,
            specialization=data.get('specialization'),
            license_number=data.get('license_number'),
            hospital=data.get('hospital'),
            experience_years=data.get('experience_years')
        )
        db.session.add(doctor)

    db.session.commit()

    log_activity(user.id, f'User registered as {role}')

    return jsonify({
        'message': f'Registration successful. Status: {status}',
        'user_id': user.id,
        'role': role,
        'status': status
    }), 201


# ---------------- LOGIN ---------------- #
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required'}), 400

    user = User.query.filter_by(email=data['email']).first()

    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401

    # Block pending users
    if user.status == 'pending':
        return jsonify({'error': 'Account pending admin approval'}), 403

    # Block suspended users
    if user.status == 'suspended':
        return jsonify({'error': 'Account suspended. Contact admin.'}), 403

    token = generate_token(user)

    log_activity(user.id, 'User logged in')

    return jsonify({
        'token': token,
        'user': user.to_dict()
    }), 200


# ---------------- PROFILE ---------------- #
@auth_bp.route('/profile', methods=['GET'])
def get_profile():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')

    if not token:
        return jsonify({'error': 'No token'}), 401

    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(payload['user_id'])

        if not user:
            return jsonify({'error': 'User not found'}), 404

        result = user.to_dict()

        if user.role == 'patient' and user.patient_profile:
            result['profile'] = user.patient_profile.to_dict()

        elif user.role == 'doctor' and user.doctor_profile:
            result['profile'] = user.doctor_profile.to_dict()

        return jsonify(result), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401

    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401