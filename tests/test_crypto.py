"""
Unit tests for cryptographic primitives.
"""
import pytest
from src.crypto.keys import generate_key_pair, derive_shared_secret, compute_key_fingerprint
from src.crypto.cipher import AESGCMCipher, encrypt_message, decrypt_message
from src.crypto.auth import compute_hmac, verify_hmac
from cryptography.exceptions import InvalidTag


def test_key_generation():
    """Test ECDH key pair generation."""
    private_key, public_key = generate_key_pair()
    
    assert len(private_key) == 32  # X25519 private key
    assert len(public_key) == 32   # X25519 public key
    assert private_key != public_key


def test_ecdh_key_exchange():
    """Test ECDH shared secret derivation."""
    # Alice generates key pair
    alice_private, alice_public = generate_key_pair()
    
    # Bob generates key pair
    bob_private, bob_public = generate_key_pair()
    
    # Alice computes shared secret using her private key + Bob's public key
    alice_shared = derive_shared_secret(alice_private, bob_public)
    
    # Bob computes shared secret using his private key + Alice's public key
    bob_shared = derive_shared_secret(bob_private, alice_public)
    
    # Shared secrets must match (Diffie-Hellman property)
    assert alice_shared == bob_shared
    assert len(alice_shared) == 32  # AES-256 key


def test_aes_gcm_encryption():
    """Test AES-256-GCM encryption and decryption."""
    key = b'0' * 32  # 256-bit key
    plaintext = b"Secret message"
    
    cipher = AESGCMCipher(key)
    ciphertext, nonce, tag = cipher.encrypt(plaintext)
    
    # Verify outputs
    assert len(nonce) == 12  # GCM nonce
    assert len(tag) == 16    # GCM tag
    assert ciphertext != plaintext
    
    # Decrypt and verify
    decrypted = cipher.decrypt(ciphertext, nonce, tag)
    assert decrypted == plaintext


def test_aes_gcm_invalid_tag():
    """Test GCM authentication failure detection."""
    key = b'0' * 32
    plaintext = b"Secret message"
    
    cipher = AESGCMCipher(key)
    ciphertext, nonce, tag = cipher.encrypt(plaintext)
    
    # Tamper with tag
    bad_tag = bytes([b ^ 0xFF for b in tag])  # Flip all bits
    
    with pytest.raises(InvalidTag):
        cipher.decrypt(ciphertext, nonce, bad_tag)


def test_hmac_computation():
    """Test HMAC-SHA256 signing and verification."""
    key = b'secret_key'
    message = b'data to authenticate'
    
    tag = compute_hmac(key, message)
    assert len(tag) == 32  # SHA-256 output
    
    # Verify correct tag
    assert verify_hmac(key, message, tag) is True
    
    # Verify incorrect tag
    bad_tag = b'0' * 32
    assert verify_hmac(key, message, bad_tag) is False


def test_message_encryption_helper():
    """Test high-level message encryption helpers."""
    key = b'0' * 32
    plaintext = "Hello, World!"
    
    encrypted = encrypt_message(key, plaintext)
    assert 'ciphertext' in encrypted
    assert 'nonce' in encrypted
    assert 'tag' in encrypted
    
    decrypted = decrypt_message(
        key,
        encrypted['ciphertext'],
        encrypted['nonce'],
        encrypted['tag']
    )
    assert decrypted == plaintext


def test_key_fingerprint():
    """Test public key fingerprint generation."""
    _, public_key = generate_key_pair()
    fingerprint = compute_key_fingerprint(public_key)
    
    assert len(fingerprint) == 64  # SHA-256 hex string
    assert all(c in '0123456789abcdef' for c in fingerprint)
