"""
Admin Routes: user management, system stats, activity logs.
"""
from flask import Blueprint, request, jsonify, g
from extensions import db
from models import User, Patient, Doctor, MedicalReport, ActivityLog
from routes.decorators import roles_required, log_activity

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')


@admin_bp.route('/dashboard', methods=['GET'])
@roles_required('admin')
def dashboard():
    total_users = User.query.count()
    total_patients = Patient.query.count()
    total_doctors = Doctor.query.count()
    total_records = MedicalReport.query.count()
    pending_users = User.query.filter_by(status='pending').count()
    recent_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
    return jsonify({
        'stats': {
            'total_users': total_users,
            'total_patients': total_patients,
            'total_doctors': total_doctors,
            'total_records': total_records,
            'pending_approvals': pending_users
        },
        'recent_activity': [log.to_dict() for log in recent_logs]
    }), 200


@admin_bp.route('/users', methods=['GET'])
@roles_required('admin')
def list_users():
    role_filter = request.args.get('role')
    status_filter = request.args.get('status')
    query = User.query
    if role_filter:
        query = query.filter_by(role=role_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)
    users = query.order_by(User.created_at.desc()).all()
    return jsonify({'users': [u.to_dict() for u in users]}), 200


@admin_bp.route('/users/<int:user_id>/approve', methods=['POST'])
@roles_required('admin')
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.status = 'active'
    db.session.commit()
    log_activity(g.current_user_id, f'Approved user {user.name}', 'user', user_id)
    return jsonify({'message': f'User {user.name} approved successfully'}), 200


@admin_bp.route('/users/<int:user_id>/suspend', methods=['POST'])
@roles_required('admin')
def suspend_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        return jsonify({'error': 'Cannot suspend admin accounts'}), 403
    user.status = 'suspended'
    db.session.commit()
    log_activity(g.current_user_id, f'Suspended user {user.name}', 'user', user_id)
    return jsonify({'message': f'User {user.name} suspended'}), 200


@admin_bp.route('/users/<int:user_id>', methods=['DELETE'])
@roles_required('admin')
def delete_user(user_id):
    if user_id == g.current_user_id:
        return jsonify({'message': 'Cannot delete your own account.'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found.'}), 404

    if user.role == 'admin':
        return jsonify({'message': 'Cannot delete admin accounts.'}), 403

    user_name = user.name

    try:
        # Must delete in this exact order to avoid FK constraint errors
        # activity_logs.user_id is NOT NULL so DELETE, never UPDATE to NULL
        db.session.execute(
            db.text("DELETE FROM activity_logs WHERE user_id = :uid"),
            {"uid": user_id}
        )
        db.session.execute(
            db.text("DELETE FROM medical_reports WHERE patient_id = :uid"),
            {"uid": user_id}
        )
        db.session.execute(
            db.text("UPDATE medical_reports SET doctor_id = NULL WHERE doctor_id = :uid"),
            {"uid": user_id}
        )
        db.session.execute(
            db.text("DELETE FROM patients WHERE user_id = :uid"),
            {"uid": user_id}
        )
        db.session.execute(
            db.text("DELETE FROM doctors WHERE user_id = :uid"),
            {"uid": user_id}
        )
        db.session.execute(
            db.text("DELETE FROM users WHERE id = :uid"),
            {"uid": user_id}
        )
        db.session.commit()
        return jsonify({'message': f'User "{user_name}" deleted successfully.'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Delete failed: {str(e)}'}), 500


@admin_bp.route('/logs', methods=['GET'])
@roles_required('admin')
def activity_logs():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return jsonify({
        'logs': [log.to_dict() for log in logs.items],
        'total': logs.total,
        'pages': logs.pages,
        'current_page': page
    }), 200


@admin_bp.route('/records', methods=['GET'])
@roles_required('admin')
def all_records():
    records = MedicalReport.query.order_by(MedicalReport.created_at.desc()).all()
    return jsonify({'records': [r.to_dict() for r in records]}), 200


@admin_bp.route('/create-doctor', methods=['POST'])
@roles_required('admin')
def create_doctor():
    from crypto.ecdsa_module import generate_ecdsa_keypair
    from crypto.ecdh_module import generate_ecdh_keypair
    from crypto.ecdsa_module import serialize_private_key as ep, serialize_public_key as epub
    from crypto.ecdh_module import serialize_private_key as hp, serialize_public_key as hpub

    data = request.get_json()
    required = ['name', 'email', 'password', 'specialization', 'license_number']
    if not all(k in data for k in required):
        return jsonify({'error': 'Missing required fields'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 409

    ecdsa_priv, ecdsa_pub = generate_ecdsa_keypair()
    ecdh_priv, ecdh_pub = generate_ecdh_keypair()

    user = User(
        name=data['name'],
        email=data['email'],
        role='doctor',
        status='active',
        ecdsa_public_key=epub(ecdsa_pub),
        ecdsa_private_key=ep(ecdsa_priv),
        ecdh_public_key=hpub(ecdh_pub),
        ecdh_private_key=hp(ecdh_priv)
    )
    user.set_password(data['password'])
    db.session.add(user)
    db.session.flush()

    doctor = Doctor(
        user_id=user.id,
        specialization=data['specialization'],
        license_number=data['license_number'],
        hospital=data.get('hospital', ''),
        experience_years=data.get('experience_years', 0)
    )
    db.session.add(doctor)
    db.session.commit()

    log_activity(g.current_user_id, f'Created doctor account for {user.name}', 'user', user.id)

    return jsonify({
        'message': 'Doctor account created',
        'user_id': user.id,
        'doctor_id': doctor.doctor_id
    }), 201
