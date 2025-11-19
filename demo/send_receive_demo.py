"""
CLI demo: Full end-to-end encrypted messaging flow.

This script demonstrates:
1. User registration (Alice and Bob)
2. Key exchange
3. Message encryption and sending
4. Message retrieval and decryption
"""
import requests
import sys

BASE_URL = "http://localhost:8000"


def register(email: str, password: str):
    """Register new user."""
    response = requests.post(f"{BASE_URL}/auth/register", json={
        "email": email,
        "password": password
    })
    if response.status_code == 200:
        print(f"✅ Registered {email}")
        return response.json()
    else:
        print(f"❌ Registration failed: {response.json()}")
        sys.exit(1)


def login(email: str, password: str):
    """Login and get access token."""
    response = requests.post(f"{BASE_URL}/auth/login", json={
        "email": email,
        "password": password
    })
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Logged in as {email}")
        return data["access_token"], data["user_id"]
    else:
        print(f"❌ Login failed: {response.json()}")
        sys.exit(1)


def send_message(token: str, recipient_id: int, plaintext: str):
    """Send encrypted message."""
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(f"{BASE_URL}/messages/send", 
        headers=headers,
        json={
            "recipient_id": recipient_id,
            "plaintext": plaintext
        }
    )
    if response.status_code == 200:
        print(f"✅ Message sent (ID: {response.json()['message_id']})")
        return response.json()
    else:
        print(f"❌ Send failed: {response.json()}")
        sys.exit(1)


def get_inbox(token: str):
    """Fetch encrypted messages."""
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/messages/inbox", headers=headers)
    if response.status_code == 200:
        messages = response.json()
        print(f"✅ Inbox: {len(messages)} messages")
        return messages
    else:
        print(f"❌ Inbox fetch failed: {response.json()}")
        sys.exit(1)


def decrypt_message(token: str, message_id: int):
    """Decrypt specific message."""
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/messages/decrypt/{message_id}", headers=headers)
    if response.status_code == 200:
        plaintext = response.json()["plaintext"]
        print(f"✅ Decrypted: '{plaintext}'")
        return plaintext
    else:
        print(f"❌ Decryption failed: {response.json()}")
        sys.exit(1)


def main():
    """Run full demo."""
    print("=" * 60)
    print("SECURE MESSAGING DEMO - END-TO-END ENCRYPTION")
    print("=" * 60)
    print()
    
    # Step 1: Register Alice and Bob
    print("📝 Step 1: Register users")
    alice_data = register("alice@example.com", "alice_password123")
    bob_data = register("bob@example.com", "bob_password456")
    print()
    
    # Step 2: Login
    print("🔐 Step 2: Login users")
    alice_token, alice_id = login("alice@example.com", "alice_password123")
    bob_token, bob_id = login("bob@example.com", "bob_password456")
    print()
    
    # Step 3: Alice sends encrypted message to Bob
    print("📨 Step 3: Alice sends encrypted message to Bob")
    message_text = "Hello Bob! This message is end-to-end encrypted. 🔒"
    send_message(alice_token, bob_id, message_text)
    print()
    
    # Step 4: Bob checks inbox
    print("📬 Step 4: Bob checks inbox")
    bob_messages = get_inbox(bob_token)
    if bob_messages:
        print(f"📦 Encrypted message preview:")
        msg = bob_messages[0]
        print(f"   Sender ID: {msg['sender_id']}")
        print(f"   Ciphertext: {msg['ciphertext'][:64]}... (truncated)")
        print(f"   Nonce: {msg['nonce']}")
        print(f"   Tag: {msg['tag']}")
        print()
        
        # Step 5: Bob decrypts message
        print("🔓 Step 5: Bob decrypts message")
        decrypted = decrypt_message(bob_token, msg['message_id'])
        print()
        
        # Verify
        print("✨ Verification:")
        print(f"   Original:  '{message_text}'")
        print(f"   Decrypted: '{decrypted}'")
        print(f"   Match: {'✅ YES' if message_text == decrypted else '❌ NO'}")
    else:
        print("❌ No messages in inbox")
    
    print()
    print("=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    print("⚠️  Make sure the server is running: python -m src.main")
    print()
    main()
