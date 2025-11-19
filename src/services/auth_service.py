"""
Authentication service: user registration, login, password verification.
"""
from sqlalchemy.orm import Session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import HTTPException, status
from ..models import User, KeyPair
from ..crypto.keys import generate_key_pair
from ..utils.helpers import create_access_token, generate_refresh_token
from ..config import settings

# Initialize Argon2 password hasher with OWASP recommended parameters
# Time cost: iterations (higher = slower but more secure)
# Memory cost: RAM usage in KB (higher = harder to parallelize with GPUs)
# Parallelism: number of threads (balance security vs server load)
ph = PasswordHasher(
    time_cost=settings.argon2_time_cost,
    memory_cost=settings.argon2_memory_cost,
    parallelism=settings.argon2_parallelism,
)


def register_user(db: Session, email: str, password: str) -> dict:
    """
    Register new user with email and password.
    
    Process:
    1. Check if user already exists
    2. Hash password with Argon2id
    3. Generate ECDH key pair for encryption
    4. Store user and keys in database
    
    Args:
        db: Database session
        email: User email (unique identifier)
        password: Plaintext password (will be hashed)
    
    Returns:
        dict: {
            "user_id": int,
            "email": str,
            "public_key": bytes
        }
    
    Raises:
        HTTPException: If user already exists
    """
    # Check if user exists
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Hash password with Argon2id
    # Argon2id = hybrid of Argon2i (side-channel resistant) and Argon2d (GPU-resistant)
    password_hash = ph.hash(password)
    
    # Create user
    user = User(email=email, password_hash=password_hash)
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Generate ECDH key pair for end-to-end encryption
    private_key_bytes, public_key_bytes = generate_key_pair()
    
    key_pair = KeyPair(
        user_id=user.id,
        private_key=private_key_bytes,  # TODO: Encrypt at rest in production
        public_key=public_key_bytes
    )
    db.add(key_pair)
    db.commit()
    
    return {
        "user_id": user.id,
        "email": user.email,
        "public_key": public_key_bytes.hex()  # Hex-encoded for JSON response
    }


def login_user(db: Session, email: str, password: str) -> dict:
    """
    Authenticate user and issue JWT tokens.
    
    Args:
        db: Database session
        email: User email
        password: Plaintext password
    
    Returns:
        dict: {
            "access_token": str,
            "token_type": "bearer",
            "user_id": int,
            "email": str
        }
    
    Raises:
        HTTPException: If credentials are invalid
    """
    # Fetch user
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Verify password
    try:
        ph.verify(user.password_hash, password)
    except VerifyMismatchError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Check if password hash needs rehashing (Argon2 parameters updated)
    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(password)
        db.commit()
    
    # Create access token
    access_token = create_access_token(data={"sub": user.email, "user_id": user.id})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "email": user.email
    }


def get_user_by_email(db: Session, email: str) -> User:
    """Fetch user by email."""
    return db.query(User).filter(User.email == email).first()


def get_user_by_id(db: Session, user_id: int) -> User:
    """Fetch user by ID."""
    return db.query(User).filter(User.id == user_id).first()
