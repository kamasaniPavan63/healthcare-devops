"""
Doctor Routes: view patients, access medical records, decrypt data.
"""
import json
from flask import Blueprint, request, jsonify, g
from extensions import db
from models import User, Patient, Doctor, MedicalReport
from routes.decorators import roles_required, log_activity
from crypto.aes_module import decrypt_data, decrypt_key_from_storage
from crypto.ecdsa_module import verify_record_signature
from crypto.sha256_module import verify_record_hash

doctor_bp = Blueprint('doctor', __name__, url_prefix='/api/doctor')


@doctor_bp.route('/dashboard', methods=['GET'])
@roles_required('doctor')
def dashboard():
    doctor = Doctor.query.filter_by(user_id=g.current_user_id).first()
    if not doctor:
        return jsonify({'error': 'Doctor profile not found'}), 404

    total_records = MedicalReport.query.filter_by(doctor_id=doctor.doctor_id).count()
    recent_records = (MedicalReport.query
                      .filter_by(doctor_id=doctor.doctor_id)
                      .order_by(MedicalReport.created_at.desc())
                      .limit(5).all())

    patient_ids = db.session.query(MedicalReport.patient_id).filter_by(
        doctor_id=doctor.doctor_id).distinct().all()

    return jsonify({
        'doctor': doctor.to_dict(),
        'stats': {
            'total_records': total_records,
            'total_patients': len(patient_ids)
        },
        'recent_records': [r.to_dict() for r in recent_records]
    }), 200


@doctor_bp.route('/patients', methods=['GET'])
@roles_required('doctor')
def list_patients():
    doctor = Doctor.query.filter_by(user_id=g.current_user_id).first()
    if not doctor:
        return jsonify({'error': 'Doctor profile not found'}), 404

    patient_ids = db.session.query(MedicalReport.patient_id).filter_by(
        doctor_id=doctor.doctor_id).distinct().all()
    patient_ids = [pid[0] for pid in patient_ids]

    patients = []
    for pid in patient_ids:
        p = Patient.query.get(pid)
        if p:
            user = User.query.get(p.user_id)
            info = p.to_dict()
            info['name'] = user.name if user else 'Unknown'
            info['email'] = user.email if user else ''
            patients.append(info)

    return jsonify({'patients': patients}), 200


@doctor_bp.route('/records', methods=['GET'])
@roles_required('doctor')
def get_records():
    doctor = Doctor.query.filter_by(user_id=g.current_user_id).first()
    if not doctor:
        return jsonify({'error': 'Doctor profile not found'}), 404

    patient_id = request.args.get('patient_id', type=int)
    query = MedicalReport.query.filter_by(doctor_id=doctor.doctor_id)

    if patient_id:
        query = query.filter_by(patient_id=patient_id)

    records = query.order_by(MedicalReport.created_at.desc()).all()

    return jsonify({'records': [r.to_dict() for r in records]}), 200


# ✅🔥 FULLY FIXED DECRYPT FUNCTION
@doctor_bp.route('/records/<int:report_id>/decrypt', methods=['GET'])
@roles_required('doctor', 'admin')
def decrypt_record(report_id):

    report = MedicalReport.query.get_or_404(report_id)
    user = User.query.get(g.current_user_id)

    # ---------------- DOCTOR ACCESS CONTROL ---------------- #
    if user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=g.current_user_id).first()

        if not doctor:
            return jsonify({'error': 'Doctor profile not found'}), 404

        if report.doctor_id and report.doctor_id != doctor.doctor_id:
            has_access = MedicalReport.query.filter_by(
                doctor_id=doctor.doctor_id,
                patient_id=report.patient_id
            ).first()

            if not has_access:
                return jsonify({'error': 'Access denied to this record'}), 403

    # ---------------- ADMIN ACCESS ---------------- #
    # Admin has full access

    try:
        encrypted_payload = report.get_encrypted_payload()

        # Verify hash
        hash_ok = verify_record_hash(
            encrypted_payload,
            report.patient_id,
            report.doctor_id or 0,
            report.report_type,
            report.hash_value
        )

        # Verify signature
        sig_ok = False
        if report.signer_public_key and report.signature:
            sig_ok = verify_record_signature(
                report.hash_value,
                report.signature,
                report.signer_public_key
            )

        # Decrypt AES key
        try:
            aes_key = decrypt_key_from_storage(
                json.loads(report.wrapped_key) if report.wrapped_key else report.hash_value
            )
        except Exception:
            import base64
            aes_key = base64.b64decode(report.wrapped_key or '')

        # Decrypt data
        decrypted = decrypt_data(encrypted_payload, aes_key)

        print("DECRYPT SUCCESS:", decrypted)  # Debug log

        log_activity(g.current_user_id, f'Decrypted report {report_id}', 'report', report_id)

        return jsonify({
            'report_id': report_id,
            'report_type': report.report_type,
            'created_at': report.created_at.isoformat(),
            'integrity_check': hash_ok,
            'signature_valid': sig_ok,
            'data': decrypted
        }), 200

    except Exception as e:
        print("DECRYPT ERROR:", str(e))  # Debug log
        return jsonify({'error': str(e)}), 500


@doctor_bp.route('/profile', methods=['GET'])
@roles_required('doctor')
def get_profile():
    doctor = Doctor.query.filter_by(user_id=g.current_user_id).first()
    if not doctor:
        return jsonify({'error': 'Doctor profile not found'}), 404

    user = User.query.get(g.current_user_id)

    result = doctor.to_dict()
    result['name'] = user.name
    result['email'] = user.email

    return jsonify(result), 200