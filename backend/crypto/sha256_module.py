"""
SHA-256 Hashing Module
Used for data integrity verification of medical records.
"""
import hashlib
import json
import hmac


def hash_data(data: dict) -> str:
    """
    Generate SHA-256 hash of a dictionary.
    Keys are sorted for deterministic output.
    Returns hex string.
    """
    serialized = json.dumps(data, sort_keys=True).encode('utf-8')
    return hashlib.sha256(serialized).hexdigest()


def hash_string(text: str) -> str:
    """Generate SHA-256 hash of a plain string."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def hash_bytes(data: bytes) -> str:
    """Generate SHA-256 hash of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_record(encrypted_payload: dict, patient_id: int,
                doctor_id: int, report_type: str) -> str:
    """
    Generate a composite hash for a medical record.
    Includes encrypted data + metadata for full integrity.
    """
    record_content = {
        'encrypted_data': encrypted_payload,
        'patient_id': patient_id,
        'doctor_id': doctor_id,
        'report_type': report_type
    }
    return hash_data(record_content)


def verify_hash(data: dict, expected_hash: str) -> bool:
    """Verify data matches expected SHA-256 hash."""
    computed = hash_data(data)
    return hmac.compare_digest(computed, expected_hash)


def verify_record_hash(encrypted_payload: dict, patient_id: int,
                       doctor_id: int, report_type: str,
                       expected_hash: str) -> bool:
    """Verify integrity of a medical record."""
    computed = hash_record(encrypted_payload, patient_id, doctor_id, report_type)
    return hmac.compare_digest(computed, expected_hash)


def hash_password(password: str, salt: str = None) -> str:
    """
    Hash a password using SHA-256 with salt.
    Note: Werkzeug's generate_password_hash is preferred in auth flows.
    """
    if salt:
        return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    return hashlib.sha256(password.encode('utf-8')).hexdigest()
