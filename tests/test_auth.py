"""
Unit tests for authentication service.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.db import Base
from src.models import User, KeyPair
from src.services.auth_service import register_user, login_user
from fastapi import HTTPException


@pytest.fixture
def db_session():
    """Create in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_user_registration(db_session):
    """Test user registration with password hashing."""
    result = register_user(db_session, "test@example.com", "secure_password123")
    
    assert "user_id" in result
    assert result["email"] == "test@example.com"
    assert "public_key" in result
    
    # Verify user in database
    user = db_session.query(User).filter(User.email == "test@example.com").first()
    assert user is not None
    assert user.password_hash.startswith("$argon2id$")  # Argon2id hash prefix
    
    # Verify key pair created
    key_pair = db_session.query(KeyPair).filter(KeyPair.user_id == user.id).first()
    assert key_pair is not None
    assert len(key_pair.public_key) == 32


def test_duplicate_registration(db_session):
    """Test that duplicate email registration fails."""
    register_user(db_session, "test@example.com", "password1")
    
    with pytest.raises(HTTPException) as exc_info:
        register_user(db_session, "test@example.com", "password2")
    
    assert exc_info.value.status_code == 400
    assert "already registered" in exc_info.value.detail


def test_user_login(db_session):
    """Test user login with correct credentials."""
    register_user(db_session, "test@example.com", "correct_password")
    
    result = login_user(db_session, "test@example.com", "correct_password")
    
    assert "access_token" in result
    assert result["token_type"] == "bearer"
    assert result["email"] == "test@example.com"


def test_login_wrong_password(db_session):
    """Test login failure with incorrect password."""
    register_user(db_session, "test@example.com", "correct_password")
    
    with pytest.raises(HTTPException) as exc_info:
        login_user(db_session, "test@example.com", "wrong_password")
    
    assert exc_info.value.status_code == 401
    assert "Invalid credentials" in exc_info.value.detail


def test_login_nonexistent_user(db_session):
    """Test login failure for non-existent user."""
    with pytest.raises(HTTPException) as exc_info:
        login_user(db_session, "nonexistent@example.com", "password")
    
    assert exc_info.value.status_code == 401
