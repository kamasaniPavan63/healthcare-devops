"""
Medical Routes: upload and manage encrypted medical records.
"""

import json
from flask import Blueprint, request, jsonify, g
from extensions import db
from models import Patient, Doctor, MedicalReport
from routes.decorators import token_required, roles_required, log_activity
from crypto.aes_module import generate_aes_key, encrypt_data, encrypt_key_for_storage
from crypto.ecdsa_module import sign_record_hash
from crypto.sha256_module import hash_record

medical_bp = Blueprint('medical', __name__, url_prefix='/api/medical')


# ✅ UPDATED REPORT TYPES (MATCHES FRONTEND)
VALID_REPORT_TYPES = [
    'vital_signs',
    'blood_test',
    'urine_test',
    'imaging',
    'ecg',
    'prescription',
    'vaccination',
    'surgery',
    'allergy',
    'diabetes',
    'thyroid',
    'other'
]

print("✅ medical_routes.py LOADED - types:", VALID_REPORT_TYPES)  # ADD THIS LINE

# ✅ UPDATED SCHEMAS (BASED ON YOUR UI)
REPORT_SCHEMAS = {

    'vital_signs': [
        'blood_pressure_systolic', 'blood_pressure_diastolic',
        'heart_rate', 'oxygen_saturation',
        'body_temperature', 'respiratory_rate',
        'height', 'weight', 'bmi',
        'clinical_notes', 'recorded_by', 'datetime'
    ],

    'blood_test': [
        'hemoglobin', 'hematocrit', 'rbc', 'wbc', 'platelets', 'mcv',
        'glucose', 'cholesterol', 'hdl', 'ldl', 'triglycerides',
        'creatinine', 'bun', 'alt', 'ast', 'sodium', 'potassium',
        'lab_name', 'sample_date', 'notes'
    ],

    'urine_test': [
        'colour', 'appearance', 'ph', 'specific_gravity',
        'protein', 'glucose', 'ketones', 'blood',
        'leukocyte_esterase', 'nitrites',
        'rbc', 'wbc', 'epithelial_cells', 'casts',
        'crystals', 'bacteria',
        'test_date', 'notes'
    ],

    'imaging': [
        'modality', 'body_part', 'laterality', 'views',
        'contrast', 'scan_date',
        'findings', 'impression', 'recommendations',
        'radiologist', 'centre'
    ],

    'ecg': [
        'heart_rate', 'pr_interval', 'qrs_duration',
        'qt_interval', 'qtc', 'axis',
        'rhythm', 'st_segment',
        'interpretation', 'datetime'
    ],

    'prescription': [
        'med1_name', 'med1_dosage', 'med1_route', 'med1_frequency', 'med1_duration',
        'med2_name', 'med2_dosage', 'med2_frequency', 'med2_duration',
        'med3_name', 'med3_details',
        'diagnosis', 'allergies', 'instructions',
        'followup_date', 'doctor'
    ],

    'vaccination': [
        'vaccine_name', 'manufacturer', 'batch_number',
        'dose_number', 'route', 'site',
        'date_administered', 'next_dose',
        'adverse_events', 'administered_by'
    ],

    'surgery': [
        'procedure_name', 'indication', 'date',
        'duration', 'anaesthesia', 'approach',
        'blood_loss', 'hospital',
        'findings', 'postop_instructions', 'surgeon'
    ],

    'allergy': [
        'test_type', 'date',
        'allergens', 'positive_reactions',
        'ige', 'severity',
        'symptoms', 'treatment', 'doctor'
    ],

    'diabetes': [
        'hba1c', 'fbs', 'ppbs', 'rbs',
        'insulin', 'c_peptide', 'egfr', 'microalbumin',
        'type', 'medications', 'complications', 'date'
    ],

    'thyroid': [
        'tsh', 'ft4', 'ft3', 't4', 't3',
        'anti_tpo',
        'impression', 'symptoms',
        'medications', 'date'
    ],

    'other': [
        'report_name', 'date', 'lab',
        'param1_name', 'param1_value',
        'param2_name', 'param2_value',
        'param3_name', 'param3_value',
        'param4_name', 'param4_value',
        'param5_name', 'param5_value',
        'param6_name', 'param6_value',
        'findings', 'impression', 'doctor'
    ]
}


def get_patient_for_user(user_id):
    return Patient.query.filter_by(user_id=user_id).first()


def get_doctor_for_user(user_id):
    return Doctor.query.filter_by(user_id=user_id).first()


@medical_bp.route('/upload', methods=['POST'])
@token_required
def upload_report():

    data = request.get_json()
    report_type = data.get('report_type', '').lower()
    print("VALID TYPES:", VALID_REPORT_TYPES)
    print("RECEIVED TYPE:", report_type)

    # ✅ VALIDATION FIXED
    if report_type not in VALID_REPORT_TYPES:
        return jsonify({
            'error': f'Invalid report type: {report_type}',
            'valid_types': VALID_REPORT_TYPES
        }), 400

    report_data = data.get('report_data', {})

    current_user = g.current_user

    if current_user.role == 'patient':
        patient = get_patient_for_user(current_user.id)
        patient_id = patient.patient_id
        doctor_id = data.get('doctor_id')
        signer_user = current_user

    elif current_user.role == 'doctor':
        doctor = get_doctor_for_user(current_user.id)
        patient_id = data.get('patient_id')
        doctor_id = doctor.doctor_id
        signer_user = current_user

    else:
        return jsonify({'error': 'Unauthorized'}), 403

    # 🔐 Encryption
    aes_key = generate_aes_key()
    encrypted_payload = encrypt_data(report_data, aes_key)

    # 🔑 Hash
    record_hash = hash_record(
        encrypted_payload,
        patient_id,
        doctor_id or 0,
        report_type
    )

    # ✍️ Signature
    if signer_user.ecdsa_private_key:
        signature = sign_record_hash(record_hash, signer_user.ecdsa_private_key)
        signer_pub_key = signer_user.ecdsa_public_key
    else:
        signature = 'NO_SIGNATURE'
        signer_pub_key = None

    # 🔒 Key wrapping
    wrapped_key = encrypt_key_for_storage(aes_key)

    # 💾 Save
    report = MedicalReport(
        patient_id=patient_id,
        doctor_id=doctor_id,
        report_type=report_type,
        encrypted_data=json.dumps(encrypted_payload),
        wrapped_key=wrapped_key,
        hash_value=record_hash,
        signature=signature,
        signer_public_key=signer_pub_key
    )

    db.session.add(report)
    db.session.commit()

    log_activity(
        g.current_user_id,
        f'Uploaded {report_type} report',
        'report',
        report.report_id
    )

    return jsonify({
    'message': 'Report uploaded successfully',
    'report_id': report.report_id,
    'report_type': report_type,

    # ✅ MATCH FRONTEND NAMES
    'sha256': record_hash,
    'sig': signature,
    'algorithm': 'AES-256 + ECDSA + SHA-256'
}), 201
@medical_bp.route('/delete_report/<int:report_id>', methods=['DELETE'])
@roles_required('admin')
def delete_report(report_id):
    try:
        report = MedicalReport.query.get(report_id)

        if not report:
            return jsonify({'error': 'Report not found'}), 404

        db.session.delete(report)
        db.session.commit()

        return jsonify({'message': 'Report deleted successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500