"""
ECDH (Elliptic Curve Diffie-Hellman) Key Exchange Module
Used for secure AES key exchange between system components.
"""
import base64
import json
from cryptography.hazmat.primitives.asymmetric.ec import (
    generate_private_key, ECDH, EllipticCurvePublicKey,
    EllipticCurvePrivateKey
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


def generate_ecdh_keypair():
    """
    Generate an ECDH key pair using SECP384R1 curve.
    Returns (private_key, public_key) objects.
    """
    private_key = generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key: EllipticCurvePublicKey) -> str:
    """Serialize public key to PEM string for storage/transmission."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')


def serialize_private_key(private_key: EllipticCurvePrivateKey) -> str:
    """Serialize private key to PEM string."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')


def deserialize_public_key(pem_str: str) -> EllipticCurvePublicKey:
    """Load a public key from PEM string."""
    return serialization.load_pem_public_key(
        pem_str.encode('utf-8'), backend=default_backend()
    )


def deserialize_private_key(pem_str: str) -> EllipticCurvePrivateKey:
    """Load a private key from PEM string."""
    return serialization.load_pem_private_key(
        pem_str.encode('utf-8'), password=None, backend=default_backend()
    )


def derive_shared_secret(private_key: EllipticCurvePrivateKey,
                         peer_public_key: EllipticCurvePublicKey) -> bytes:
    """
    Perform ECDH key exchange and derive a shared AES-256 key.
    Both parties must use their own private key and the other's public key.
    """
    shared_key = private_key.exchange(ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'healthcare-ecdh-aes-key',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key


def wrap_aes_key_with_ecdh(aes_key: bytes, recipient_public_key_pem: str) -> dict:
    """
    Wrap an AES key using ECDH: generate ephemeral keypair,
    derive shared secret, XOR-wrap the AES key.
    Returns a payload the recipient can unwrap with their private key.
    """
    ephemeral_private, ephemeral_public = generate_ecdh_keypair()
    recipient_pub = deserialize_public_key(recipient_public_key_pem)
    shared_secret = derive_shared_secret(ephemeral_private, recipient_pub)

    # XOR the AES key with the shared secret
    wrapped = bytes(a ^ b for a, b in zip(aes_key, shared_secret))

    return {
        'ephemeral_public_key': serialize_public_key(ephemeral_public),
        'wrapped_key': base64.b64encode(wrapped).decode('utf-8')
    }


def unwrap_aes_key_with_ecdh(wrapped_payload: dict,
                              recipient_private_key_pem: str) -> bytes:
    """
    Unwrap an AES key using the recipient's ECDH private key.
    """
    recipient_priv = deserialize_private_key(recipient_private_key_pem)
    ephemeral_pub = deserialize_public_key(wrapped_payload['ephemeral_public_key'])
    shared_secret = derive_shared_secret(recipient_priv, ephemeral_pub)

    wrapped = base64.b64decode(wrapped_payload['wrapped_key'])
    aes_key = bytes(a ^ b for a, b in zip(wrapped, shared_secret))
    return aes_key
