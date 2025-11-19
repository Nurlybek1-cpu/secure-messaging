"""
ECDH key exchange using X25519 (Curve25519).

Why X25519?
- Fast, constant-time operations (side-channel resistant)
- 128-bit security level (equivalent to AES-256 when used with proper KDF)
- Industry standard (used in Signal, TLS 1.3, WireGuard)
- Simpler than NIST curves (no point compression issues)
"""
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os


def generate_key_pair() -> tuple[bytes, bytes]:
    """
    Generate a new ECDH X25519 key pair.
    
    Returns:
        tuple: (private_key_bytes, public_key_bytes)
        - private_key: 32 bytes (keep secret!)
        - public_key: 32 bytes (share with others)
    """
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Serialize to raw bytes (no PEM wrapping for simplicity)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return private_bytes, public_bytes


def load_private_key(private_key_bytes: bytes) -> X25519PrivateKey:
    """Load X25519 private key from raw bytes."""
    return X25519PrivateKey.from_private_bytes(private_key_bytes)


def load_public_key(public_key_bytes: bytes) -> X25519PublicKey:
    """Load X25519 public key from raw bytes."""
    return X25519PublicKey.from_public_bytes(public_key_bytes)


def derive_shared_secret(private_key_bytes: bytes, peer_public_key_bytes: bytes) -> bytes:
    """
    Perform ECDH key exchange to derive shared secret.
    
    Process:
    1. Compute raw ECDH shared point (32 bytes)
    2. Derive AES-256 key using HKDF-SHA256 (key derivation function)
    
    Why HKDF?
    - Raw ECDH output has non-uniform distribution
    - HKDF extracts entropy and expands to desired key length
    - Includes optional context info for domain separation
    
    Args:
        private_key_bytes: Your private key (32 bytes)
        peer_public_key_bytes: Other party's public key (32 bytes)
    
    Returns:
        bytes: 32-byte AES-256 key (derived from shared secret)
    """
    private_key = load_private_key(private_key_bytes)
    peer_public_key = load_public_key(peer_public_key_bytes)
    
    # Perform ECDH exchange (yields 32-byte shared secret)
    shared_secret = private_key.exchange(peer_public_key)
    
    # Derive AES key using HKDF (NIST SP 800-56C compliant)
    # Info parameter provides context separation (prevents key reuse across protocols)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 requires 32-byte key
        salt=None,  # Optional: can add salt for additional entropy
        info=b"SecureMessaging-v1-AES256",  # Protocol version tag
    ).derive(shared_secret)
    
    return derived_key


def export_public_key_pem(public_key_bytes: bytes) -> str:
    """
    Export public key to PEM format (for display/verification).
    Optional: useful for key fingerprint verification UI.
    """
    public_key = load_public_key(public_key_bytes)
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')


def compute_key_fingerprint(public_key_bytes: bytes) -> str:
    """
    Compute SHA-256 fingerprint of public key for verification.
    Users can compare fingerprints out-of-band to detect MITM attacks.
    
    Returns:
        str: Hex-encoded fingerprint (64 characters)
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(public_key_bytes)
    return digest.finalize().hex()
