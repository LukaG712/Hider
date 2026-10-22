"""Encryption utilities for Hider secret management.

Uses AES-256-GCM for authenticated encryption. All secrets are encrypted
at rest. The encryption key is derived from the ENCRYPTION_KEY environment
variable using a simple key derivation.
"""

import os
import base64
import hashlib
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def get_encryption_key() -> bytes:
    """Get the 32-byte encryption key from environment.
    
    Derives a 32-byte key from the ENCRYPTION_KEY environment variable
    using SHA-256 to ensure proper key length.
    """
    raw_key = os.getenv("ENCRYPTION_KEY", "")
    if not raw_key:
        raise ValueError("ENCRYPTION_KEY environment variable is not set")
    # Derive a 32-byte key using SHA-256
    return hashlib.sha256(raw_key.encode("utf-8")).digest()


def encrypt_value(plaintext: str) -> str:
    """Encrypt a plaintext value using AES-256-GCM.
    
    Returns a base64-encoded string containing the nonce and ciphertext.
    Format: base64(nonce || ciphertext)
    """
    key = get_encryption_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # Store nonce + ciphertext together
    encrypted = nonce + ciphertext
    return base64.b64encode(encrypted).decode("ascii")


def decrypt_value(encrypted_b64: str) -> Optional[str]:
    """Decrypt an AES-256-GCM encrypted value.
    
    Returns the plaintext string or None if decryption fails.
    """
    try:
        key = get_encryption_key()
        aesgcm = AESGCM(key)
        encrypted = base64.b64decode(encrypted_b64)
        # Split nonce (12 bytes) and ciphertext
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception:
        return None


def is_encrypted(value: str) -> bool:
    """Check if a value appears to be encrypted (base64-encoded, >50 chars)."""
    if not value or len(value) < 50:
        return False
    try:
        decoded = base64.b64decode(value)
        return len(decoded) > 12  # At least nonce + some ciphertext
    except Exception:
        return False
