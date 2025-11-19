"""
Messaging service: send, receive, key exchange.
"""
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from ..models import User, KeyPair, Message
from ..crypto.cipher import AESGCMCipher
from ..crypto.auth import compute_hmac
from ..crypto.keys import derive_shared_secret
from datetime import datetime


def get_user_public_key(db: Session, user_id: int) -> bytes:
    """
    Fetch user's active public key for key exchange.
    
    Args:
        db: Database session
        user_id: Target user ID
    
    Returns:
        bytes: 32-byte X25519 public key
    
    Raises:
        HTTPException: If user or key not found
    """
    key_pair = db.query(KeyPair).filter(
        KeyPair.user_id == user_id,
        KeyPair.is_active == True
    ).first()
    
    if not key_pair:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User public key not found"
        )
    
    return key_pair.public_key


def send_message(
    db: Session,
    sender_id: int,
    recipient_id: int,
    plaintext: str
) -> dict:
    """
    Encrypt and send message from sender to recipient.
    
    Process:
    1. Fetch sender's private key and recipient's public key
    2. Perform ECDH key exchange to derive shared secret
    3. Derive encryption key and HMAC key from shared secret
    4. Encrypt plaintext with AES-256-GCM
    5. Compute HMAC over ciphertext
    6. Store encrypted message in database
    
    Args:
        db: Database session
        sender_id: Sender user ID
        recipient_id: Recipient user ID
        plaintext: Message text to encrypt
    
    Returns:
        dict: {
            "message_id": int,
            "created_at": datetime
        }
    
    Security notes:
    - Server never sees plaintext (encryption happens client-side in real system)
    - For MVP demo, encryption happens server-side but principle is same
    """
    # Fetch sender's private key
    sender_key = db.query(KeyPair).filter(
        KeyPair.user_id == sender_id,
        KeyPair.is_active == True
    ).first()
    
    if not sender_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sender key pair not found"
        )
    
    # Fetch recipient's public key
    recipient_public_key = get_user_public_key(db, recipient_id)
    
    # Perform ECDH key exchange
    shared_secret = derive_shared_secret(sender_key.private_key, recipient_public_key)
    
    # Derive encryption key (already done in derive_shared_secret via HKDF)
    encryption_key = shared_secret
    
    # Encrypt message with AES-256-GCM
    cipher = AESGCMCipher(encryption_key)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext, nonce, tag = cipher.encrypt(plaintext_bytes)
    
    # Compute HMAC for additional integrity protection
    # HMAC is computed over (ciphertext || nonce || tag)
    message_data = ciphertext + nonce + tag
    hmac_tag = compute_hmac(encryption_key, message_data)
    
    # Store encrypted message
    message = Message(
        sender_id=sender_id,
        recipient_id=recipient_id,
        ciphertext=ciphertext,
        nonce=nonce,
        tag=tag,
        hmac=hmac_tag
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    
    return {
        "message_id": message.id,
        "created_at": message.created_at
    }


def get_messages(db: Session, user_id: int, limit: int = 50) -> list[dict]:
    """
    Fetch encrypted messages for user (inbox).
    
    Args:
        db: Database session
        user_id: Recipient user ID
        limit: Maximum messages to return
    
    Returns:
        list[dict]: List of encrypted messages with metadata
    """
    messages = db.query(Message).filter(
        Message.recipient_id == user_id
    ).order_by(Message.created_at.desc()).limit(limit).all()
    
    return [
        {
            "message_id": msg.id,
            "sender_id": msg.sender_id,
            "ciphertext": msg.ciphertext.hex(),
            "nonce": msg.nonce.hex(),
            "tag": msg.tag.hex(),
            "hmac": msg.hmac.hex(),
            "created_at": msg.created_at.isoformat()
        }
        for msg in messages
    ]


def decrypt_message(
    db: Session,
    recipient_id: int,
    message_id: int
) -> str:
    """
    Decrypt message for recipient.
    
    Process:
    1. Fetch encrypted message from database
    2. Fetch recipient's private key and sender's public key
    3. Perform ECDH key exchange (same shared secret as sender)
    4. Verify HMAC
    5. Decrypt with AES-256-GCM
    
    Args:
        db: Database session
        recipient_id: Recipient user ID
        message_id: Message ID to decrypt
    
    Returns:
        str: Decrypted plaintext message
    
    Raises:
        HTTPException: If message not found or authentication fails
    """
    # Fetch message
    message = db.query(Message).filter(
        Message.id == message_id,
        Message.recipient_id == recipient_id
    ).first()
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found"
        )
    
    # Fetch recipient's private key
    recipient_key = db.query(KeyPair).filter(
        KeyPair.user_id == recipient_id,
        KeyPair.is_active == True
    ).first()
    
    # Fetch sender's public key
    sender_public_key = get_user_public_key(db, message.sender_id)
    
    # Perform ECDH key exchange (yields same shared secret as sender)
    shared_secret = derive_shared_secret(recipient_key.private_key, sender_public_key)
    encryption_key = shared_secret
    
    # Verify HMAC first (authenticate before decrypt)
    message_data = message.ciphertext + message.nonce + message.tag
    expected_hmac = compute_hmac(encryption_key, message_data)
    
    import hmac as hmac_module
    if not hmac_module.compare_digest(expected_hmac, message.hmac):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message authentication failed (HMAC mismatch)"
        )
    
    # Decrypt message
    cipher = AESGCMCipher(encryption_key)
    try:
        plaintext_bytes = cipher.decrypt(message.ciphertext, message.nonce, message.tag)
        plaintext = plaintext_bytes.decode('utf-8')
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Decryption failed: {str(e)}"
        )
    
    # Mark as read
    if not message.read_at:
        message.read_at = datetime.utcnow()
        db.commit()
    
    return plaintext
