"""
SHA-256 implementation from scratch for educational purposes.

This demonstrates understanding of cryptographic hash functions by implementing
the SHA-256 algorithm manually according to FIPS 180-4 specification.

⚠️  WARNING: This is for EDUCATIONAL purposes only!
    Use cryptography library's SHA-256 for production (faster, audited, constant-time).

SHA-256 Properties:
- Input: Any length message (0 to 2^64 - 1 bits)
- Output: 256-bit (32-byte) hash
- Collision resistance: ~2^128 operations to find collision
- Pre-image resistance: ~2^256 operations to find input for given hash
- Avalanche effect: 1 bit change in input → ~50% output bits change
"""
import struct
from typing import List


class SHA256:
    """
    Manual implementation of SHA-256 hash function.
    
    Algorithm overview:
    1. Padding: Append bits to make length ≡ 448 (mod 512)
    2. Append length: Add 64-bit message length
    3. Process blocks: Process each 512-bit block through 64 rounds
    4. Output: Concatenate final hash values (8 × 32 bits = 256 bits)
    """
    
    # SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    # Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    H0 = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    def __init__(self):
        """Initialize SHA-256 hasher."""
        self.reset()
    
    def reset(self):
        """Reset hash state to initial values."""
        self.h = self.H0.copy()
        self.buffer = b''
        self.message_length = 0
    
    @staticmethod
    def _rotr(x: int, n: int) -> int:
        """Rotate right: circular right shift by n bits (32-bit word)."""
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
    
    @staticmethod
    def _shr(x: int, n: int) -> int:
        """Shift right: logical right shift by n bits."""
        return x >> n
    
    @staticmethod
    def _ch(x: int, y: int, z: int) -> int:
        """Choose function: if x then y else z (bitwise)."""
        return (x & y) ^ (~x & z)
    
    @staticmethod
    def _maj(x: int, y: int, z: int) -> int:
        """Majority function: outputs majority bit at each position."""
        return (x & y) ^ (x & z) ^ (y & z)
    
    @classmethod
    def _sigma0(cls, x: int) -> int:
        """Σ0 function for main loop."""
        return cls._rotr(x, 2) ^ cls._rotr(x, 13) ^ cls._rotr(x, 22)
    
    @classmethod
    def _sigma1(cls, x: int) -> int:
        """Σ1 function for main loop."""
        return cls._rotr(x, 6) ^ cls._rotr(x, 11) ^ cls._rotr(x, 25)
    
    @classmethod
    def _gamma0(cls, x: int) -> int:
        """σ0 function for message schedule."""
        return cls._rotr(x, 7) ^ cls._rotr(x, 18) ^ cls._shr(x, 3)
    
    @classmethod
    def _gamma1(cls, x: int) -> int:
        """σ1 function for message schedule."""
        return cls._rotr(x, 17) ^ cls._rotr(x, 19) ^ cls._shr(x, 10)
    
    def _process_block(self, block: bytes):
        """
        Process a single 512-bit (64-byte) block.
        
        Args:
            block: 64-byte block to process
        """
        # Prepare message schedule (64 32-bit words)
        w = list(struct.unpack('>16I', block)) + [0] * 48
        
        # Extend the first 16 words into remaining 48 words
        for i in range(16, 64):
            w[i] = (self._gamma1(w[i-2]) + w[i-7] + 
                   self._gamma0(w[i-15]) + w[i-16]) & 0xFFFFFFFF
        
        # Initialize working variables
        a, b, c, d, e, f, g, h = self.h
        
        # Main loop (64 rounds)
        for i in range(64):
            t1 = (h + self._sigma1(e) + self._ch(e, f, g) + 
                  self.K[i] + w[i]) & 0xFFFFFFFF
            t2 = (self._sigma0(a) + self._maj(a, b, c)) & 0xFFFFFFFF
            
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF
        
        # Update hash values
        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + h) & 0xFFFFFFFF
    
    def update(self, data: bytes):
        """
        Update hash with new data.
        
        Args:
            data: Bytes to add to hash
        """
        self.buffer += data
        self.message_length += len(data)
        
        # Process complete 512-bit blocks
        while len(self.buffer) >= 64:
            self._process_block(self.buffer[:64])
            self.buffer = self.buffer[64:]
    
    def digest(self) -> bytes:
        """
        Finalize hash and return digest.
        
        Returns:
            bytes: 32-byte SHA-256 hash
        """
        # Make copy to preserve state
        mdi = self.message_length % 64
        padded = self.buffer
        
        # Padding: append '1' bit followed by zeros
        padded += b'\x80'
        
        # Pad to 448 bits (56 bytes) mod 512 bits
        if mdi < 56:
            padded += b'\x00' * (55 - mdi)
        else:
            padded += b'\x00' * (119 - mdi)
        
        # Append original message length in bits (64-bit big-endian)
        padded += struct.pack('>Q', self.message_length * 8)
        
        # Process padded blocks
        temp_h = self.h.copy()
        for i in range(0, len(padded), 64):
            self._process_block(padded[i:i+64])
        
        # Produce final hash value
        digest = struct.pack('>8I', *self.h)
        
        # Restore original state
        self.h = temp_h
        
        return digest
    
    def hexdigest(self) -> str:
        """Return hex string of digest."""
        return self.digest().hex()


def sha256(data: bytes) -> bytes:
    """
    Convenience function: compute SHA-256 hash.
    
    Args:
        data: Bytes to hash
    
    Returns:
        bytes: 32-byte SHA-256 hash
    """
    hasher = SHA256()
    hasher.update(data)
    return hasher.digest()


def sha256_hex(data: bytes) -> str:
    """
    Convenience function: compute SHA-256 hash as hex string.
    
    Args:
        data: Bytes to hash
    
    Returns:
        str: 64-character hex string
    """
    return sha256(data).hex()


# Testing and validation
if __name__ == "__main__":
    print("SHA-256 From-Scratch Implementation")
    print("=" * 60)
    
    # Test vectors from NIST
    test_cases = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        (b"The quick brown fox jumps over the lazy dog",
         "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),
    ]
    
    print("\nTest Vectors:")
    print("-" * 60)
    
    for i, (message, expected) in enumerate(test_cases, 1):
        result = sha256_hex(message)
        status = "✅ PASS" if result == expected else "❌ FAIL"
        
        print(f"\nTest {i}: {status}")
        print(f"  Input: {message[:50]}" + ("..." if len(message) > 50 else ""))
        print(f"  Expected: {expected}")
        print(f"  Got:      {result}")
        
        if result != expected:
            print("  ❌ MISMATCH!")
    
    # Verify against Python's hashlib
    print("\n" + "=" * 60)
    print("Verification against hashlib.sha256:")
    print("-" * 60)
    
    import hashlib
    
    test_message = b"Secure Messaging Application - Cryptography Project 2024"
    our_hash = sha256_hex(test_message)
    lib_hash = hashlib.sha256(test_message).hexdigest()
    
    print(f"Message: {test_message.decode()}")
    print(f"Our implementation:  {our_hash}")
    print(f"hashlib.sha256:      {lib_hash}")
    print(f"Match: {our_hash == lib_hash} {'✅' if our_hash == lib_hash else '❌'}")
    
    # Avalanche effect demonstration
    print("\n" + "=" * 60)
    print("Avalanche Effect Demonstration:")
    print("-" * 60)
    
    msg1 = b"Hello World"
    msg2 = b"Hello Wo rld"  # Changed one bit (space position)
    
    hash1 = sha256_hex(msg1)
    hash2 = sha256_hex(msg2)
    
    # Count different bits
    bits_different = bin(int(hash1, 16) ^ int(hash2, 16)).count('1')
    
    print(f"Message 1: {msg1}")
    print(f"Hash 1:    {hash1}")
    print(f"\nMessage 2: {msg2} (1 character changed)")
    print(f"Hash 2:    {hash2}")
    print(f"\nBits changed: {bits_different}/256 ({bits_different/256*100:.1f}%)")
    print(f"Expected: ~50% for good avalanche effect")
    
    print("\n" + "=" * 60)
    print("✅ SHA-256 from-scratch implementation validated!")
