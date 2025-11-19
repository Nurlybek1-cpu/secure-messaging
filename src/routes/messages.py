"""
Messaging API routes.
"""
from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from pydantic import BaseModel
from ..db import get_db
from ..services.messaging_service import send_message, get_messages, decrypt_message, get_user_public_key
from ..utils.helpers import verify_token

router = APIRouter(prefix="/messages", tags=["Messages"])


def get_current_user(authorization: str = Header(...), db: Session = Depends(get_db)) -> int:
    """
    Extract user ID from JWT token.
    
    Usage: current_user_id: int = Depends(get_current_user)
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = authorization.split(" ")[1]
    payload = verify_token(token)
    return payload.get("user_id")


class SendMessageRequest(BaseModel):
    recipient_id: int
    plaintext: str


@router.post("/send")
def send(
    request: SendMessageRequest,
    current_user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Send encrypted message to recipient.
    
    Request:
        - recipient_id: Target user ID
        - plaintext: Message text (will be encrypted)
    
    Headers:
        - Authorization: Bearer <access_token>
    
    Response:
        - message_id: Stored message ID
        - created_at: Timestamp
    """
    return send_message(db, current_user_id, request.recipient_id, request.plaintext)


@router.get("/inbox")
def inbox(
    current_user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Fetch encrypted messages for current user.
    
    Headers:
        - Authorization: Bearer <access_token>
    
    Response:
        - List of encrypted messages with metadata
    """
    return get_messages(db, current_user_id)


@router.get("/decrypt/{message_id}")
def decrypt(
    message_id: int,
    current_user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Decrypt specific message.
    
    Path:
        - message_id: Message ID to decrypt
    
    Headers:
        - Authorization: Bearer <access_token>
    
    Response:
        - plaintext: Decrypted message text
    """
    plaintext = decrypt_message(db, current_user_id, message_id)
    return {"plaintext": plaintext}


@router.get("/keys/{user_id}")
def get_public_key(user_id: int, db: Session = Depends(get_db)):
    """
    Fetch public key for user (for key exchange).
    
    Path:
        - user_id: Target user ID
    
    Response:
        - public_key: Hex-encoded X25519 public key
    """
    public_key = get_user_public_key(db, user_id)
    return {"public_key": public_key.hex()}
