"""
AES-256-GCM symmetric encryption.

Why AES-GCM?
- Authenticated encryption: provides both confidentiality AND integrity
- Fast (hardware-accelerated on modern CPUs via AES-NI)
- Nonce-based: no IV/key reuse issues if nonces are unique
- Industry standard (TLS 1.3, disk encryption, secure messaging)

CRITICAL: Never reuse (key, nonce) pair! Each message must have unique nonce.
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


class AESGCMCipher:
    """
    AES-256-GCM encryption/decryption wrapper with automatic nonce handling.
    """
    
    NONCE_SIZE = 12  # 96 bits (recommended for GCM)
    TAG_SIZE = 16  # 128 bits (authentication tag)
    
    def __init__(self, key: bytes):
        """
        Initialize cipher with 256-bit key.
        
        Args:
            key: 32-byte encryption key (from ECDH shared secret or KDF)
        
        Raises:
            ValueError: If key is not 32 bytes
        """
        if len(key) != 32:
            raise ValueError("AES-256 requires 32-byte key")
        self.cipher = AESGCM(key)
    
    def encrypt(self, plaintext: bytes, associated_data: bytes = None) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt plaintext with AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt
            associated_data: Optional additional authenticated data (AAD)
                           AAD is authenticated but not encrypted (e.g., headers, metadata)
        
        Returns:
            tuple: (ciphertext, nonce, tag)
            - ciphertext: encrypted data
            - nonce: 12-byte random nonce (must be stored with message)
            - tag: 16-byte authentication tag (proves integrity)
        
        Security notes:
        - Nonce is randomly generated using cryptographically secure RNG
        - With 96-bit nonce, probability of collision is negligible (< 2^-32 for 2^32 messages)
        - Tag is computed over (ciphertext || AAD || nonce) - prevents tampering
        """
        # Generate cryptographically secure random nonce
        nonce = os.urandom(self.NONCE_SIZE)
        
        # Encrypt and authenticate in one operation
        # GCM mode automatically appends authentication tag to ciphertext
        ciphertext_with_tag = self.cipher.encrypt(nonce, plaintext, associated_data)
        
        # Split ciphertext and tag (tag is last 16 bytes)
        ciphertext = ciphertext_with_tag[:-self.TAG_SIZE]
        tag = ciphertext_with_tag[-self.TAG_SIZE:]
        
        return ciphertext, nonce, tag
    
    def decrypt(self, ciphertext: bytes, nonce: bytes, tag: bytes, associated_data: bytes = None) -> bytes:
        """
        Decrypt and verify AES-256-GCM ciphertext.
        
        Args:
            ciphertext: Encrypted data
            nonce: 12-byte nonce used during encryption
            tag: 16-byte authentication tag
            associated_data: Same AAD provided during encryption (if any)
        
        Returns:
            bytes: Decrypted plaintext
        
        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
                This indicates tampering, corruption, or wrong key!
        
        Security notes:
        - Authentication check happens BEFORE decryption (prevents padding oracle attacks)
        - Timing should be constant regardless of tag validity (library handles this)
        """
        # Reconstruct ciphertext with tag (GCM expects them together)
        ciphertext_with_tag = ciphertext + tag
        
        # Decrypt and verify in one operation
        # Raises InvalidTag exception if authentication fails
        plaintext = self.cipher.decrypt(nonce, ciphertext_with_tag, associated_data)
        
        return plaintext


def encrypt_message(key: bytes, plaintext: str) -> dict:
    """
    High-level helper: encrypt text message.
    
    Returns:
        dict: {
            'ciphertext': bytes,
            'nonce': bytes,
            'tag': bytes
        }
    """
    cipher = AESGCMCipher(key)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext, nonce, tag = cipher.encrypt(plaintext_bytes)
    
    return {
        'ciphertext': ciphertext,
        'nonce': nonce,
        'tag': tag
    }


def decrypt_message(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> str:
    """
    High-level helper: decrypt text message.
    
    Raises:
        InvalidTag: If message was tampered with
        UnicodeDecodeError: If decrypted data is not valid UTF-8
    """
    cipher = AESGCMCipher(key)
    plaintext_bytes = cipher.decrypt(ciphertext, nonce, tag)
    return plaintext_bytes.decode('utf-8')
