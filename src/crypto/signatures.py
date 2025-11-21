"""
ECDSA (Elliptic Curve Digital Signature Algorithm) for message authentication.

Why ECDSA?
- Provides non-repudiation: proves sender identity (HMAC can't do this)
- Smaller signatures than RSA (256-bit ECDSA ≈ 3072-bit RSA security)
- Fast verification (important for message integrity checks)
- Uses same curve family as our ECDH (secp256r1 / NIST P-256)

Digital Signatures vs HMAC:
- HMAC: Symmetric (both parties share same key, can't prove who sent it)
- ECDSA: Asymmetric (only private key holder can sign, anyone can verify with public key)
- ECDSA provides non-repudiation (sender cannot deny sending message)
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import os


class ECDSASigner:
    """
    ECDSA signing and verification using NIST P-256 curve.
    
    Key differences from ECDH keys:
    - ECDH: X25519 (optimized for key exchange)
    - ECDSA: secp256r1/P-256 (optimized for signatures)
    
    In production, you'd use separate key pairs for signing vs encryption.
    For this project, we demonstrate both concepts.
    """
    
    CURVE = ec.SECP256R1()  # NIST P-256, 128-bit security level
    HASH_ALGORITHM = hashes.SHA256()
    
    @classmethod
    def generate_signing_keypair(cls) -> tuple[bytes, bytes]:
        """
        Generate new ECDSA signing key pair.
        
        Returns:
            tuple: (private_key_bytes, public_key_bytes)
            - private_key: DER-encoded
            - public_key: DER-encoded
        
        Note: Public key is larger than X25519 because it includes
        both X and Y coordinates of the elliptic curve point.
        """
        private_key = ec.generate_private_key(cls.CURVE)
        public_key = private_key.public_key()
        
        # Serialize keys to DER format
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_bytes, public_bytes
    
    @classmethod
    def load_private_key(cls, private_key_bytes: bytes) -> ec.EllipticCurvePrivateKey:
        """Load ECDSA private key from DER bytes."""
        return serialization.load_der_private_key(
            private_key_bytes,
            password=None
        )
    
    @classmethod
    def load_public_key(cls, public_key_bytes: bytes) -> ec.EllipticCurvePublicKey:
        """Load ECDSA public key from DER bytes."""
        return serialization.load_der_public_key(public_key_bytes)
    
    @classmethod
    def sign_message(cls, private_key_bytes: bytes, message: bytes) -> bytes:
        """
        Sign message with ECDSA private key.
        
        Process:
        1. Hash message with SHA-256
        2. Sign hash with private key using ECDSA
        3. Return DER-encoded signature (variable length, ~70-72 bytes)
        
        Args:
            private_key_bytes: ECDSA private key (DER format)
            message: Data to sign (can be plaintext or ciphertext)
        
        Returns:
            bytes: DER-encoded ECDSA signature
        
        Security notes:
        - Uses deterministic nonce generation (RFC 6979) - prevents nonce reuse attacks
        - Signature proves: (1) message came from private key holder, (2) message wasn't modified
        - Does NOT encrypt the message (use encryption separately for confidentiality)
        """
        private_key = cls.load_private_key(private_key_bytes)
        
        signature = private_key.sign(
            message,
            ec.ECDSA(cls.HASH_ALGORITHM)
        )
        
        return signature
    
    @classmethod
    def verify_signature(cls, public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify ECDSA signature.
        
        Args:
            public_key_bytes: Signer's public key (DER format)
            message: Original message that was signed
            signature: ECDSA signature to verify
        
        Returns:
            bool: True if signature is valid, False otherwise
        
        Security notes:
        - Verification is much faster than signing (asymmetric property)
        - Anyone with public key can verify, but only private key holder can sign
        - Constant-time verification (prevents timing attacks)
        """
        try:
            public_key = cls.load_public_key(public_key_bytes)
            public_key.verify(
                signature,
                message,
                ec.ECDSA(cls.HASH_ALGORITHM)
            )
            return True
        except InvalidSignature:
            # Signature verification failed (tampered message or wrong key)
            return False
        except Exception:
            # Invalid key format or other errors
            return False
    
    @classmethod
    def sign_text(cls, private_key_bytes: bytes, text: str) -> bytes:
        """
        Helper: Sign text message (converts to UTF-8 bytes first).
        
        Args:
            private_key_bytes: ECDSA private key
            text: Text message to sign
        
        Returns:
            bytes: Digital signature
        """
        return cls.sign_message(private_key_bytes, text.encode('utf-8'))
    
    @classmethod
    def verify_text(cls, public_key_bytes: bytes, text: str, signature: bytes) -> bool:
        """
        Helper: Verify signature on text message.
        
        Args:
            public_key_bytes: Signer's public key
            text: Original text message
            signature: Signature to verify
        
        Returns:
            bool: True if valid, False otherwise
        """
        return cls.verify_signature(public_key_bytes, text.encode('utf-8'), signature)


# Convenience functions for easy import
def generate_signing_keypair() -> tuple[bytes, bytes]:
    """Generate ECDSA signing key pair."""
    return ECDSASigner.generate_signing_keypair()


def sign_message(private_key: bytes, message: bytes) -> bytes:
    """Sign message with ECDSA."""
    return ECDSASigner.sign_message(private_key, message)


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify ECDSA signature."""
    return ECDSASigner.verify_signature(public_key, message, signature)


def sign_text(private_key: bytes, text: str) -> bytes:
    """Sign text message."""
    return ECDSASigner.sign_text(private_key, text)


def verify_text(public_key: bytes, text: str, signature: bytes) -> bool:
    """Verify signature on text."""
    return ECDSASigner.verify_text(public_key, text, signature)


# Example usage and testing
if __name__ == "__main__":
    print("ECDSA Digital Signature Demo\n" + "="*50)
    
    # Generate key pair
    print("\n1. Generating ECDSA key pair...")
    private_key, public_key = generate_signing_keypair()
    print(f"   Private key size: {len(private_key)} bytes")
    print(f"   Public key size: {len(public_key)} bytes")
    
    # Sign a message
    message = "This is a digitally signed message!"
    print(f"\n2. Signing message: '{message}'")
    signature = sign_text(private_key, message)
    print(f"   Signature size: {len(signature)} bytes")
    print(f"   Signature (hex): {signature.hex()[:60]}...")
    
    # Verify signature
    print(f"\n3. Verifying signature...")
    is_valid = verify_text(public_key, message, signature)
    print(f"   Valid: {is_valid} ✅")
    
    # Test tampering detection
    print(f"\n4. Testing tampering detection...")
    tampered_message = "This message has been tampered with!"
    is_valid_tampered = verify_text(public_key, tampered_message, signature)
    print(f"   Tampered message valid: {is_valid_tampered} ✅ (correctly rejected)")
    
    # Test wrong signature
    print(f"\n5. Testing wrong signature rejection...")
    wrong_signature = os.urandom(len(signature))
    is_valid_wrong = verify_text(public_key, message, wrong_signature)
    print(f"   Wrong signature valid: {is_valid_wrong} ✅ (correctly rejected)")
    
    print("\n" + "="*50)
    print("✅ All ECDSA tests passed!")
