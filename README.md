# Secure Messaging Application

End-to-end encrypted messaging system using ECDH key exchange, AES-256-GCM encryption, and HMAC authentication.

## Features

- ✅ User registration with Argon2id password hashing
- ✅ JWT-based authentication (access tokens)
- ✅ ECDH (X25519) key exchange for deriving shared secrets
- ✅ AES-256-GCM symmetric encryption for message confidentiality
- ✅ HMAC-SHA256 for message integrity verification
- ✅ REST API with FastAPI
- ✅ SQLite database (upgrade to PostgreSQL for production)
- ✅ Comprehensive unit tests

## Security Properties

- **Confidentiality**: Only sender and recipient can read messages (end-to-end encryption)
- **Integrity**: Any tampering detected via GCM authentication tag + HMAC
- **Authentication**: Cryptographic proof of sender identity
- **Password Security**: Argon2id hashing with OWASP-recommended parameters

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

1. Clone repository
```bash
git clone <repository-url>
cd secure-messaging
```

2. Create virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Create environment file
```bash
cp .env.example .env
```

5. Edit .env and set SECRET_KEY and JWT_SECRET_KEY (min 32 characters each)

### Generate Secret Keys

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Copy output to `.env` for `SECRET_KEY` and `JWT_SECRET_KEY`.

## Running the Application

### Start Server

```bash
python -m src.main
```

Server runs at `http://localhost:8000`

API documentation available at `http://localhost:8000/docs`

### Run Demo

In a separate terminal (with server running):

```bash
python demo/send_receive_demo.py
```

### Run Tests

```bash
pytest tests/ -v
```

## API Endpoints

### Authentication

**Register User**

```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure_password"
}
```

**Login**

```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure_password"
}
```

### Messaging

**Send Message**

```http
POST /messages/send
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "recipient_id": 2,
  "plaintext": "Secret message"
}
```

**Get Inbox**

```http
GET /messages/inbox
Authorization: Bearer <access_token>
```

**Decrypt Message**

```http
GET /messages/decrypt/{message_id}
Authorization: Bearer <access_token>
```

## Project Structure

```
secure-messaging/
├── src/
│   ├── crypto/         # Cryptographic primitives (ECDH, AES, HMAC)
│   ├── routes/         # API endpoints
│   ├── services/       # Business logic
│   ├── models.py       # Database models
│   └── main.py         # Application entry point
├── tests/              # Unit and integration tests
├── docs/               # Architecture and security documentation
└── demo/               # CLI demonstration script
```

## Security Notes

### Cryptographic Parameters

- **Password Hashing**: Argon2id (time=2, memory=64MB, parallelism=4)
- **Key Exchange**: ECDH with X25519 curve
- **Encryption**: AES-256-GCM (256-bit key, 96-bit nonce)
- **Message Auth**: HMAC-SHA256 (256-bit output)
- **JWT Signing**: HS256 (HMAC-SHA256)

### Production Hardening

⚠️ **This MVP requires additional hardening for production:**

1. **HTTPS/TLS**: Deploy behind reverse proxy with valid TLS certificate
2. **Key Storage**: Encrypt private keys at rest (currently stored plaintext in DB)
3. **Rate Limiting**: Add rate limits to prevent brute-force attacks
4. **Input Validation**: Enhance validation for all user inputs
5. **Database**: Migrate to PostgreSQL with connection pooling
6. **Monitoring**: Add logging and security event monitoring
7. **Forward Secrecy**: Implement ephemeral keys (see bonus section)

## License

MIT License (see LICENSE file)
