import os
from src.crypto.signatures import (
    generate_signing_keypair,
    sign_text,
    verify_text,
)
from src.crypto.manual_sha256 import sha256_hex
import hashlib

def test_digital_signatures():
    private_key, public_key = generate_signing_keypair()
    message = "This is a digitally signed message!"
    signature = sign_text(private_key, message)
    assert verify_text(public_key, message, signature)
    tampered = "This message has been tampered!"
    assert not verify_text(public_key, tampered, signature)
    wrong_sig = os.urandom(len(signature))
    assert not verify_text(public_key, message, wrong_sig)

def test_manual_sha256_vectors():
    cases = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (b"The quick brown fox jumps over the lazy dog",
         "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),
    ]
    for message, expected in cases:
        assert sha256_hex(message) == expected

def test_manual_sha256_vs_hashlib():
    msg = b"Secure Messaging Application"
    assert sha256_hex(msg) == hashlib.sha256(msg).hexdigest()

def test_manual_sha256_avalanche():
    msg1 = b"Hello World"
    msg2 = b"Hello World!"
    hash1 = sha256_hex(msg1)
    hash2 = sha256_hex(msg2)
    bits_diff = bin(int(hash1, 16) ^ int(hash2, 16)).count('1')
    assert bits_diff > 100 and bits_diff < 180  # ~50% changed
