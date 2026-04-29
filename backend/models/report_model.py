"""
MedicalReport and ActivityLog models.
"""
import json
from datetime import datetime
from extensions import db
from datetime import timedelta


class MedicalReport(db.Model):
    __tablename__ = 'medical_reports'

    report_id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.patient_id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.doctor_id'), nullable=True)
    report_type = db.Column(db.String(50), nullable=False)  # vital_signs, blood_test, imaging, prescription

    # Encrypted payload (JSON string of AES-GCM output)
    encrypted_data = db.Column(db.Text, nullable=False)

    # AES key wrapped via ECDH for the doctor
    wrapped_key = db.Column(db.Text, nullable=True)

    # Integrity & authenticity
    hash_value = db.Column(db.String(64), nullable=False)  # SHA-256 hex
    signature = db.Column(db.Text, nullable=False)         # ECDSA base64

    # Who signed it
    signer_public_key = db.Column(db.Text, nullable=True)

    status = db.Column(db.String(20), default='active')  # active, archived
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def get_encrypted_payload(self) -> dict:
        return json.loads(self.encrypted_data)

    def to_dict(self, include_encrypted=False):
        data = {
            'report_id': self.report_id,
            'patient_id': self.patient_id,
            'doctor_id': self.doctor_id,
            'report_type': self.report_type,
            'hash_value': self.hash_value,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
        }
        if include_encrypted:
            data['encrypted_data'] = self.encrypted_data
            data['signature'] = self.signature
        return data


class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'

    log_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    resource = db.Column(db.String(100), nullable=True)
    resource_id = db.Column(db.Integer, nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='activity_logs')

    # ✅ FIX MUST BE INSIDE CLASS
    def to_dict(self):
        from datetime import timedelta

        ist_time = self.timestamp + timedelta(hours=5, minutes=30)

        return {
            'log_id': self.log_id,
            'user_id': self.user_id,
            'user_name': self.user.name if self.user else 'Unknown',
            'action': self.action,
            'resource': self.resource,
            'resource_id': self.resource_id,
            'timestamp': ist_time.isoformat()
        }