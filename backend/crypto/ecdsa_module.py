"""
ECDSA (Elliptic Curve Digital Signature Algorithm) Module
Used for digital signatures to verify sender authenticity.
"""
import base64
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    generate_private_key, EllipticCurvePrivateKey, EllipticCurvePublicKey
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def generate_ecdsa_keypair():
    """
    Generate an ECDSA key pair using SECP256K1 curve.
    Returns (private_key, public_key).
    """
    private_key = generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(private_key: EllipticCurvePrivateKey) -> str:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')


def serialize_public_key(public_key: EllipticCurvePublicKey) -> str:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')


def deserialize_private_key(pem_str: str) -> EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(
        pem_str.encode('utf-8'), password=None, backend=default_backend()
    )


def deserialize_public_key(pem_str: str) -> EllipticCurvePublicKey:
    return serialization.load_pem_public_key(
        pem_str.encode('utf-8'), backend=default_backend()
    )


def sign_data(data: dict, private_key_pem: str) -> str:
    """
    Sign a dictionary using ECDSA + SHA-256.
    Returns base64-encoded DER signature.
    """
    private_key = deserialize_private_key(private_key_pem)
    message = json.dumps(data, sort_keys=True).encode('utf-8')
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode('utf-8')


def verify_signature(data: dict, signature_b64: str, public_key_pem: str) -> bool:
    """
    Verify an ECDSA signature against a dictionary.
    Returns True if valid, False otherwise.
    """
    try:
        public_key = deserialize_public_key(public_key_pem)
        message = json.dumps(data, sort_keys=True).encode('utf-8')
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False


def sign_record_hash(record_hash: str, private_key_pem: str) -> str:
    """
    Sign a record's SHA-256 hash for integrity + authenticity.
    """
    private_key = deserialize_private_key(private_key_pem)
    message = record_hash.encode('utf-8')
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode('utf-8')


def verify_record_signature(record_hash: str, signature_b64: str,
                             public_key_pem: str) -> bool:
    """Verify a record hash signature."""
    try:
        public_key = deserialize_public_key(public_key_pem)
        message = record_hash.encode('utf-8')
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False
