"""
Utility functions for JWT tokens and error handling.
"""
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi import HTTPException, status
from ..config import settings
import secrets


def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    """
    Create JWT access token.
    
    Args:
        data: Payload to encode (e.g., {"sub": user_email})
        expires_delta: Token lifetime (default: 15 minutes)
    
    Returns:
        str: Encoded JWT token
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )
    return encoded_jwt


def verify_token(token: str) -> dict:
    """
    Verify and decode JWT token.
    
    Raises:
        HTTPException: If token is invalid or expired
    
    Returns:
        dict: Decoded payload
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm]
        )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def generate_refresh_token() -> str:
    """
    Generate cryptographically secure refresh token.
    
    Returns:
        str: 32-byte hex token (64 characters)
    """
    return secrets.token_hex(32)
