"""
User, Patient, Doctor models.
"""
from datetime import datetime
from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='patient')  # admin, doctor, patient
    status = db.Column(db.String(20), nullable=False, default='pending')  # active, pending, suspended
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # ECDSA keys for digital signatures
    ecdsa_public_key = db.Column(db.Text, nullable=True)
    ecdsa_private_key = db.Column(db.Text, nullable=True)  # encrypted in production

    # ECDH keys for key exchange
    ecdh_public_key = db.Column(db.Text, nullable=True)
    ecdh_private_key = db.Column(db.Text, nullable=True)

    # Relationships
    patient_profile = db.relationship('Patient', backref='user', uselist=False, cascade='all, delete-orphan')
    doctor_profile = db.relationship('Doctor', backref='user', uselist=False, cascade='all, delete-orphan')

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'role': self.role,
            'status': self.status,
            'created_at': self.created_at.isoformat()
        }


class Patient(db.Model):
    __tablename__ = 'patients'

    patient_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    age = db.Column(db.Integer, nullable=True)
    gender = db.Column(db.String(20), nullable=True)
    blood_group = db.Column(db.String(10), nullable=True)
    medical_history = db.Column(db.Text, nullable=True)
    emergency_contact = db.Column(db.String(150), nullable=True)

    # Medical records
    records = db.relationship('MedicalReport', foreign_keys='MedicalReport.patient_id',
                               backref='patient', lazy='dynamic', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'patient_id': self.patient_id,
            'user_id': self.user_id,
            'age': self.age,
            'gender': self.gender,
            'blood_group': self.blood_group,
            'medical_history': self.medical_history,
            'emergency_contact': self.emergency_contact
        }


class Doctor(db.Model):
    __tablename__ = 'doctors'

    doctor_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    specialization = db.Column(db.String(100), nullable=True)
    license_number = db.Column(db.String(50), unique=True, nullable=True)
    hospital = db.Column(db.String(150), nullable=True)
    experience_years = db.Column(db.Integer, nullable=True)

    # Records authored by this doctor
    authored_records = db.relationship('MedicalReport', foreign_keys='MedicalReport.doctor_id',
                                        backref='doctor', lazy='dynamic')

    def to_dict(self):
        return {
            'doctor_id': self.doctor_id,
            'user_id': self.user_id,
            'specialization': self.specialization,
            'license_number': self.license_number,
            'hospital': self.hospital,
            'experience_years': self.experience_years
        }
