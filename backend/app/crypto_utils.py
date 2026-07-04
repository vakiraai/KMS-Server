# server/app/crypto_utils.py
import os
import hashlib
import hmac
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class CryptoError(Exception):
    """Custom exception raised for cryptographic failures."""
    pass

def generate_key() -> bytes:
    """Generates a random 32-byte (256-bit) cryptographically secure key."""
    return os.urandom(32)

def encrypt_data(data: bytes, key: bytes, aad: bytes = None) -> dict:
    """
    Encrypts raw bytes using AES-256-GCM.
    Returns a dict with iv, ciphertext, and tag encoded in base64.
    """
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    if aad:
        encryptor.authenticate_additional_data(aad)
        
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    return {
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(encryptor.tag).decode("utf-8")
    }

def decrypt_data(enc_dict: dict, key: bytes, aad: bytes = None) -> bytes:
    """
    Decrypts an AES-256-GCM encrypted dict payload.
    """
    try:
        iv = base64.b64decode(enc_dict["iv"])
        ciphertext = base64.b64decode(enc_dict["ciphertext"])
        tag = base64.b64decode(enc_dict["tag"])
        
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        
        if aad:
            decryptor.authenticate_additional_data(aad)
            
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        raise CryptoError("Decryption failed") from None

def derive_kek(fingerprint_hash: str, secret: bytes) -> bytes:
    """
    Derives a KEK dynamically from the client's fingerprint hash and a vendor secret.
    """
    # Use HKDF-like KDF via HMAC-SHA256
    h = hmac.new(secret, fingerprint_hash.encode("utf-8"), hashlib.sha256)
    return h.digest()

def generate_activation_code(fingerprint_hash: str, license_id: str, secret: bytes) -> str:
    """
    Generates a 16-character alphanumeric activation code: XXXX-XXXX-XXXX-XXXX
    Derived from the fingerprint hash, license ID, and server key.
    """
    message = f"{fingerprint_hash}:{license_id}".encode("utf-8")
    h = hmac.new(secret, message, hashlib.sha256).digest()
    
    # Encode to Base32 to ensure human-readable alphanumeric strings (excluding ambiguous chars like I, O, 1, 0)
    # Using python's base64.b32encode
    b32 = base64.b32encode(h).decode("utf-8").replace("=", "")
    
    # Take the first 16 characters and format it as XXXX-XXXX-XXXX-XXXX
    code = b32[:16]
    return f"{code[0:4]}-{code[4:8]}-{code[8:12]}-{code[12:16]}"
