"""
Authentication API routes.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from ..db import get_db
from ..services.auth_service import register_user, login_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@router.post("/register")
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    """
    Register new user.
    
    Request:
        - email: Valid email address
        - password: Plaintext password (min 8 characters recommended)
    
    Response:
        - user_id: Unique user identifier
        - email: Registered email
        - public_key: Hex-encoded ECDH public key
    """
    return register_user(db, request.email, request.password)


@router.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    """
    Authenticate user and receive JWT access token.
    
    Request:
        - email: User email
        - password: User password
    
    Response:
        - access_token: JWT bearer token (15 min expiry)
        - token_type: "bearer"
        - user_id: User identifier
        - email: User email
    """
    return login_user(db, request.email, request.password)
