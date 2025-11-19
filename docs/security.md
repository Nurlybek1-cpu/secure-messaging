# Security Documentation

## Threat Model

### Assets

1. **Message Plaintext**: Most sensitive—only sender/recipient should access
2. **User Credentials**: Email + password for authentication
3. **Encryption Keys**: Private keys for ECDH key exchange
4. **Session Tokens**: JWT access tokens

### Attackers

1. **Passive Network Attacker**: Eavesdrops on network traffic
2. **Active Network Attacker**: MITM attacks, message tampering
3. **Malicious Server Operator**: Has database access
4. **Database Breach**: Attacker gains database dump

### Security Goals

- **Confidentiality**: Prevent unauthorized message reading
- **Integrity**: Detect any message tampering
- **Authentication**: Verify message sender identity
- **Forward Secrecy**: Past messages safe if keys compromised (bonus feature)

### Countermeasures

| Threat | Mitigation |
|--------|-----------|
| Network eavesdropping | End-to-end encryption (AES-256-GCM) |
| Message tampering | GCM authentication tag + HMAC verification |
| Password theft | Argon2id hashing (GPU-resistant) |
| Server snooping | Server never receives plaintext (E2EE) |
| MITM key exchange | Key fingerprint verification (bonus) |
| Session hijacking | Short-lived JWTs (15 min expiry) |
| Brute force login | Rate limiting (production enhancement) |

## Cryptographic Rationale

### Why X25519 for ECDH?

- **Performance**: Faster than NIST P-256
- **Security**: Constant-time operations (side-channel resistant)
- **Simplicity**: No point compression issues
- **Industry Standard**: Used in Signal, TLS 1.3, WireGuard
- **Security Level**: 128-bit (equivalent to AES-256 with proper KDF)

### Why AES-256-GCM?

- **Authenticated Encryption**: Combines confidentiality + integrity
- **Performance**: Hardware-accelerated (AES-NI on modern CPUs)
- **Nonce-Based**: No IV/key reuse issues
- **Industry Standard**: Required by NSA Suite B, used in TLS 1.3
- **Patent-Free**: No licensing restrictions

**Alternative Considered**: ChaCha20-Poly1305 (better for software-only, but AES-NI makes GCM faster)

### Why HMAC-SHA256 in addition to GCM?

- **Defense in Depth**: GCM tag authenticates ciphertext; HMAC authenticates full message structure
- **Implementation Safety**: Prevents bugs where GCM tag is improperly verified
- **Metadata Authentication**: Can authenticate fields not in GCM AAD

**Note**: In production, GCM tag alone is sufficient if implemented correctly. HMAC is educational here.

### Why Argon2id for Passwords?

- **Memory-Hard**: Resistant to GPU/ASIC brute force
- **Hybrid Design**: Combines Argon2i (side-channel resistant) + Argon2d (GPU-resistant)
- **Configurable Cost**: Can increase as hardware improves
- **Winner**: Password Hashing Competition (PHC) 2015
- **OWASP Recommended**: Current best practice

**Parameters (MVP)**: time=2, memory=64MB, parallelism=4

**Production**: Increase to time=3, memory=128MB based on server capacity

## Attack Scenarios

### 1. Passive Network Eavesdropping

**Attack**: Attacker captures all network traffic

**Mitigation**: 
- Transport layer: TLS 1.3 (production)
- Application layer: End-to-end encryption (server never sees plaintext)
- Result: Attacker sees only ciphertext

### 2. Malicious Server Operator

**Attack**: Database administrator accesses message storage

**Mitigation**:
- All messages stored as ciphertext (no plaintext in database)
- Server lacks private keys to decrypt (keys stored client-side in production)
- Result: Server sees encrypted blobs, cannot read content

**Current Limitation (MVP)**: Private keys stored in database for demo purposes. Production must store keys client-side only.

### 3. Message Tampering

**Attack**: Attacker modifies ciphertext in transit or storage

**Mitigation**:
- GCM authentication tag (16 bytes) verifies ciphertext integrity
- HMAC tag verifies entire message structure
- Verification happens before decryption
- Result: Decryption fails with InvalidTag exception

### 4. Replay Attacks

**Attack**: Attacker captures and re-sends old encrypted message

**Mitigation (MVP)**: 
- Nonce uniqueness prevents identical ciphertext for same plaintext
- Timestamps in metadata can detect old messages

**Production Enhancement**: Add sequence numbers and session IDs

### 5. Password Brute Force

**Attack**: Attacker tries to guess passwords offline (after database breach)

**Mitigation**:
- Argon2id hashing makes each guess computationally expensive
- Memory-hard algorithm prevents GPU acceleration
- High time/memory cost slows brute force

**Additional Production Defense**: Rate limiting on login endpoint

## Common Pitfalls Avoided

### ❌ Nonce Reuse

**Danger**: Reusing (key, nonce) pair leaks plaintext via XOR

**Solution**: Generate fresh random nonce for each message (os.urandom)

### ❌ Weak Random Number Generation

**Danger**: Predictable nonces/keys allow attacks

**Solution**: Use cryptographically secure RNG (os.urandom, secrets module)

### ❌ Padding Oracle Attacks

**Danger**: Error messages leak decryption info in CBC mode

**Solution**: Use authenticated encryption (GCM) which verifies before decrypt

### ❌ Timing Attacks

**Danger**: Time difference between "wrong password" and "wrong user" leaks info

**Solution**: 
- Constant-time password comparison (Argon2 library handles this)
- Constant-time HMAC comparison (hmac.compare_digest)
- Generic error messages ("Invalid credentials")

### ❌ Hardcoded Secrets

**Danger**: Keys/passwords in source code compromise security

**Solution**: Environment variables (.env file) for all secrets

## Recommendations for Hardening

### Critical (Before Production)

1. **TLS/HTTPS**: Deploy behind nginx/Apache with Let's Encrypt certificate
2. **Key Storage**: Move private keys to client-side only (never server storage)
3. **Input Validation**: Sanitize all inputs (email format, password length, message size)
4. **Rate Limiting**: Prevent brute force (e.g., 5 login attempts per IP per hour)
5. **Logging**: Security event logging (failed logins, suspicious patterns)

### Important

6. **Database Migration**: PostgreSQL with connection pooling
7. **Session Management**: Implement refresh token rotation
8. **Error Messages**: Never leak sensitive info in errors
9. **Dependency Updates**: Regularly update cryptography libraries
10. **Security Audit**: Professional code review before launch

### Advanced

11. **Forward Secrecy**: Implement ephemeral ECDH keys (see bonus section)
12. **Key Verification**: Out-of-band fingerprint comparison
13. **Multi-Device**: Per-device key pairs with device management
14. **Message Deletion**: Secure deletion with overwrite
15. **Metadata Privacy**: Padding/dummy traffic to hide patterns

## Cryptographic Parameters (Summary)

```python
# Argon2id (password hashing)
time_cost = 2           # iterations
memory_cost = 65536     # 64 MB
parallelism = 4         # threads

# ECDH Key Exchange
curve = X25519          # Curve25519
key_size = 32           # bytes (256 bits)

# AES-GCM (symmetric encryption)
algorithm = AES-256-GCM
key_size = 32           # bytes
nonce_size = 12         # bytes (96 bits)
tag_size = 16           # bytes (128 bits)

# HMAC (message authentication)
algorithm = HMAC-SHA256
output_size = 32        # bytes

# JWT (session tokens)
algorithm = HS256
expiry = 15             # minutes
```

## Forward Secrecy (Bonus Implementation)

To achieve perfect forward secrecy, implement **ephemeral key pairs**:

1. Generate new ECDH key pair for each session/conversation
2. Derive session key from (long-term private key + ephemeral public key)
3. Delete ephemeral private key after session ends
4. Result: Compromising long-term key doesn't reveal past messages

**Reference Protocol**: Signal's Double Ratchet Algorithm (X3DH + Double Ratchet)

## Security Appendix

### Recommended Parameters

```python
# Production-Ready Configuration

# Argon2id (increase for production servers with more RAM)
ARGON2_TIME_COST = 3            # Up from MVP's 2
ARGON2_MEMORY_COST = 131072     # 128 MB (up from 64 MB)
ARGON2_PARALLELISM = 4

# JWT Token Expiry
ACCESS_TOKEN_EXPIRE_MINUTES = 15   # Short-lived
REFRESH_TOKEN_EXPIRE_DAYS = 7      # Rotate weekly

# AES-GCM Nonce
NONCE_SIZE = 12  # 96 bits (NEVER change or reuse!)

# Key Sizes
ECDH_KEY_SIZE = 32       # X25519 (256-bit)
AES_KEY_SIZE = 32        # AES-256
HMAC_KEY_SIZE = 32       # SHA-256 output
```

### Common Pitfalls to Avoid

| Pitfall | Consequence | Prevention |
|---------|-------------|------------|
| Nonce reuse | Catastrophic key recovery | Generate fresh random nonce per message |
| Weak RNG | Predictable keys/nonces | Use os.urandom() or secrets module only |
| Timing leaks | Password/HMAC brute force | Use constant-time comparison (hmac.compare_digest) |
| Error verbosity | Information disclosure | Generic errors ("Invalid credentials", not "User not found") |
| Hardcoded secrets | Key compromise | Environment variables only |
| Private key in DB | Server compromise = full break | Store keys client-side (production) |
