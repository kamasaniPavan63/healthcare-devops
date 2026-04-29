"""
Patient Routes: view own records, share with doctors.
"""
from flask import Blueprint, request, jsonify, g
from extensions import db
from models import User, Patient, Doctor, MedicalReport
from routes.decorators import roles_required, log_activity
from crypto.aes_module import decrypt_data, decrypt_key_from_storage
from crypto.ecdsa_module import verify_record_signature
from crypto.sha256_module import verify_record_hash
import json, base64

patient_bp = Blueprint('patient', __name__, url_prefix='/api/patient')


@patient_bp.route('/dashboard', methods=['GET'])
@roles_required('patient')
def dashboard():
    patient = Patient.query.filter_by(user_id=g.current_user_id).first()
    if not patient:
        return jsonify({'error': 'Patient profile not found'}), 404

    total_records = MedicalReport.query.filter_by(patient_id=patient.patient_id).count()
    recent_records = (MedicalReport.query
                      .filter_by(patient_id=patient.patient_id)
                      .order_by(MedicalReport.created_at.desc())
                      .limit(5).all())

    return jsonify({
        'patient': patient.to_dict(),
        'stats': {'total_records': total_records},
        'recent_records': [r.to_dict() for r in recent_records]
    }), 200


@patient_bp.route('/records', methods=['GET'])
@roles_required('patient')
def get_records():
    patient = Patient.query.filter_by(user_id=g.current_user_id).first()
    if not patient:
        return jsonify({'error': 'Patient profile not found'}), 404

    records = (MedicalReport.query
               .filter_by(patient_id=patient.patient_id)
               .order_by(MedicalReport.created_at.desc()).all())

    result = []
    for r in records:
        d = r.to_dict()
        # Get doctor name if assigned
        if r.doctor_id:
            doc = Doctor.query.get(r.doctor_id)
            if doc:
                u = User.query.get(doc.user_id)
                d['doctor_name'] = u.name if u else 'Unknown'
        result.append(d)

    return jsonify({'records': result}), 200


@patient_bp.route('/records/<int:report_id>/view', methods=['GET'])
@roles_required('patient')
def view_record(report_id):
    patient = Patient.query.filter_by(user_id=g.current_user_id).first()
    report = MedicalReport.query.get_or_404(report_id)

    if report.patient_id != patient.patient_id:
        return jsonify({'error': 'Access denied'}), 403

    encrypted_payload = report.get_encrypted_payload()

    # Verify integrity
    hash_ok = verify_record_hash(
        encrypted_payload,
        report.patient_id,
        report.doctor_id or 0,
        report.report_type,
        report.hash_value
    )

    # Decrypt
    try:
        aes_key = base64.b64decode(report.wrapped_key)
        decrypted = decrypt_data(encrypted_payload, aes_key)
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

    log_activity(g.current_user_id, f'Viewed own report {report_id}', 'report', report_id)

    return jsonify({
        'report_id': report_id,
        'report_type': report.report_type,
        'created_at': report.created_at.isoformat(),
        'integrity_check': hash_ok,
        'data': decrypted
    }), 200


@patient_bp.route('/profile', methods=['GET'])
@roles_required('patient')
def get_profile():
    patient = Patient.query.filter_by(user_id=g.current_user_id).first()
    if not patient:
        return jsonify({'error': 'Patient profile not found'}), 404
    user = User.query.get(g.current_user_id)
    result = patient.to_dict()
    result['name'] = user.name
    result['email'] = user.email
    return jsonify(result), 200


@patient_bp.route('/doctors', methods=['GET'])
@roles_required('patient')
def list_doctors():
    doctors = Doctor.query.join(User).filter(User.status == 'active').all()
    result = []
    for d in doctors:
        u = User.query.get(d.user_id)
        info = d.to_dict()
        info['name'] = u.name
        result.append(info)
    return jsonify({'doctors': result}), 200
