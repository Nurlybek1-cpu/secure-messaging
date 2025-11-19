"""
SQLAlchemy database models.
Stores users, key pairs, and encrypted messages.
"""
from sqlalchemy import Column, Integer, String, LargeBinary, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from .db import Base


class User(Base):
    """
    User account with authentication credentials.
    Password is hashed with Argon2id before storage.
    """
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)  # Argon2 hash
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    key_pairs = relationship("KeyPair", back_populates="user", cascade="all, delete-orphan")
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    received_messages = relationship("Message", foreign_keys="Message.recipient_id", back_populates="recipient")


class KeyPair(Base):
    """
    ECDH X25519 key pairs for end-to-end encryption.
    Private key stored encrypted at rest (future enhancement).
    Public key shared with other users for key exchange.
    """
    __tablename__ = "key_pairs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Keys stored as raw bytes
    public_key = Column(LargeBinary, nullable=False)  # 32 bytes for X25519
    private_key = Column(LargeBinary, nullable=False)  # 32 bytes (MVP: plaintext; TODO: encrypt)
    
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="key_pairs")


class Message(Base):
    """
    Encrypted messages stored on server.
    Server never sees plaintext - only ciphertext, nonce, and authentication tag.
    """
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Encrypted payload (AES-256-GCM output)
    ciphertext = Column(LargeBinary, nullable=False)
    nonce = Column(LargeBinary, nullable=False)  # 12 bytes for GCM
    tag = Column(LargeBinary, nullable=False)  # 16 bytes authentication tag
    
    # HMAC for additional integrity check (belt-and-suspenders approach)
    hmac = Column(LargeBinary, nullable=False)  # 32 bytes HMAC-SHA256
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    read_at = Column(DateTime, nullable=True)
    
    # Relationships
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="received_messages")
