"""
AES-256-GCM Encryption Module
Provides authenticated encryption for healthcare records.
"""
import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def generate_aes_key() -> bytes:
    """Generate a 256-bit (32-byte) AES key."""
    return get_random_bytes(32)


def encrypt_data(data: dict, key: bytes) -> dict:
    """
    Encrypt a dictionary of data using AES-256-GCM.
    Returns a dict with: nonce, ciphertext, tag (all base64-encoded).
    """
    plaintext = json.dumps(data).encode('utf-8')
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        'nonce': base64.b64encode(cipher.nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8')
    }


def decrypt_data(encrypted_payload: dict, key: bytes) -> dict:
    """
    Decrypt AES-256-GCM encrypted data.
    Returns the original dictionary.
    """
    nonce = base64.b64decode(encrypted_payload['nonce'])
    ciphertext = base64.b64decode(encrypted_payload['ciphertext'])
    tag = base64.b64decode(encrypted_payload['tag'])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(plaintext.decode('utf-8'))


def encrypt_key_for_storage(aes_key: bytes) -> str:
    """
    Encode the AES key as base64 for storage.
    In production, this would be wrapped with the recipient's public key via ECDH.
    """
    return base64.b64encode(aes_key).decode('utf-8')


def decrypt_key_from_storage(encoded_key: str) -> bytes:
    """Decode a base64-encoded AES key."""
    return base64.b64decode(encoded_key)
