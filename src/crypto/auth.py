"""
Message authentication using HMAC-SHA256.

Why HMAC in addition to GCM authentication tag?
- Defense in depth: GCM tag authenticates ciphertext, HMAC authenticates entire message structure
- Prevents implementation bugs where GCM tag is checked incorrectly
- Allows authentication of metadata not included in GCM AAD
- Industry practice: Signal Protocol uses both GCM and HMAC

Note: For production, you could use ONLY GCM tag (it's sufficient).
HMAC is added here for educational purposes and belt-and-suspenders security.
"""
import hmac
import hashlib


def compute_hmac(key: bytes, message: bytes) -> bytes:
    """
    Compute HMAC-SHA256 authentication tag.
    
    Args:
        key: Secret key (should be different from encryption key for key separation)
        message: Data to authenticate
    
    Returns:
        bytes: 32-byte HMAC tag
    
    Security notes:
    - HMAC is a keyed hash function (SHA-256 alone is NOT sufficient for authentication)
    - Resistant to length extension attacks (unlike raw SHA-256)
    - Use separate keys for encryption and MAC (or derive both from master key)
    """
    return hmac.new(key, message, hashlib.sha256).digest()


def verify_hmac(key: bytes, message: bytes, expected_tag: bytes) -> bool:
    """
    Verify HMAC-SHA256 authentication tag.
    
    Args:
        key: Secret key used for HMAC
        message: Data to verify
        expected_tag: HMAC tag to check against
    
    Returns:
        bool: True if tag is valid, False otherwise
    
    Security notes:
    - Uses constant-time comparison (prevents timing attacks)
    - Comparison time does NOT depend on where mismatch occurs
    """
    computed_tag = compute_hmac(key, message)
    # hmac.compare_digest() is constant-time comparison
    return hmac.compare_digest(computed_tag, expected_tag)


def derive_auth_key(shared_secret: bytes) -> bytes:
    """
    Derive separate HMAC key from shared secret.
    
    Best practice: Use different keys for encryption and authentication.
    Method: HKDF with different info parameter.
    
    Args:
        shared_secret: ECDH shared secret
    
    Returns:
        bytes: 32-byte HMAC key
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    
    hmac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"SecureMessaging-v1-HMAC",  # Different context than encryption key
    ).derive(shared_secret)
    
    return hmac_key
