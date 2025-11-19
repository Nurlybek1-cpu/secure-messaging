# Architecture Documentation

## System Overview

The Secure Messaging Application implements end-to-end encrypted messaging using modern cryptographic primitives. The system ensures that message plaintext is never visible to the server—only encrypted ciphertext is stored and transmitted.

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       Client Layer                          │
│         (Browser/CLI) - Performs encryption/decryption      │
└───────────────────────────┬─────────────────────────────────┘
                            │ HTTPS (TLS)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      API Layer (FastAPI)                    │
│         /auth/register | /auth/login | /messages/*          │
└───────────────────────────┬─────────────────────────────────┘
                            │
            ┌───────────────┼───────────────┐
            │               │               │
            ▼               ▼               ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │    Auth      │ │  Messaging   │ │    Crypto    │
    │   Service    │ │   Service    │ │    Module    │
    └───┬──────────┘ └──────┬───────┘ └──────┬───────┘
        │                   │                │
        └───────────────────┬────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Database (SQLite/PostgreSQL)                   │
│   - users (id, email, password_hash)                        │
│   - key_pairs (user_id, public_key, private_key)            │
│   - messages (sender_id, recipient_id, ciphertext, nonce)   │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow: Send Message

1. **Authentication**: User A logs in → receives JWT access token
2. **Key Exchange**: User A fetches User B's public key from server
3. **Shared Secret**: User A performs ECDH using A's private key + B's public key
4. **Key Derivation**: HKDF-SHA256 derives AES-256 key from shared secret
5. **Encryption**: AES-256-GCM encrypts plaintext → (ciphertext, nonce, tag)
6. **Authentication**: HMAC-SHA256 computed over ciphertext
7. **Transmission**: User A sends {ciphertext, nonce, tag, hmac} to server
8. **Storage**: Server stores encrypted message (never sees plaintext)

## Data Flow: Receive Message

1. **Fetch**: User B retrieves encrypted messages from inbox
2. **Key Exchange**: User B performs ECDH using B's private key + A's public key
3. **Shared Secret**: Derives same AES-256 key as User A
4. **Verification**: Verifies HMAC tag (authenticates message)
5. **Decryption**: AES-256-GCM decrypts ciphertext → plaintext
6. **Display**: User B sees original message

## Database Schema

### users

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email VARCHAR UNIQUE NOT NULL,
    password_hash VARCHAR NOT NULL,  -- Argon2id hash
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### key_pairs

```sql
CREATE TABLE key_pairs (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    public_key BLOB NOT NULL,        -- 32 bytes (X25519)
    private_key BLOB NOT NULL,       -- 32 bytes (encrypted in production)
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### messages

```sql
CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    sender_id INTEGER REFERENCES users(id),
    recipient_id INTEGER REFERENCES users(id),
    ciphertext BLOB NOT NULL,
    nonce BLOB NOT NULL,             -- 12 bytes (GCM nonce)
    tag BLOB NOT NULL,               -- 16 bytes (GCM auth tag)
    hmac BLOB NOT NULL,              -- 32 bytes (HMAC-SHA256)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    read_at DATETIME
);
```

## Technology Stack

- **Framework**: FastAPI (async Python web framework)
- **Database**: SQLAlchemy ORM with SQLite (PostgreSQL for production)
- **Cryptography**: `cryptography` library (PyCA)
- **Password Hashing**: Argon2id via `argon2-cffi`
- **JWT**: `python-jose` for token signing
- **Testing**: pytest

## Security Layers

| Layer | Protection | Implementation |
|-------|-----------|----------------|
| Transport | Eavesdropping | HTTPS/TLS 1.3 (production) |
| Authentication | Impersonation | JWT tokens + password hashing |
| Message Confidentiality | Server/network snooping | End-to-end AES-256-GCM |
| Message Integrity | Tampering | GCM auth tag + HMAC |
| Key Exchange | MITM | ECDH + key fingerprint verification |
| Password Storage | Database breach | Argon2id hashing |
