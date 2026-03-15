from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
import jwt
from app.core.config import get_settings
import hashlib
import bcrypt
import hmac
import hashlib
import time
import json
import base64
from cryptography.fernet import Fernet

settings = get_settings()

# Password hashing context — bcrypt is the algorithm
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(plain_password: str) -> str:
    """
    Pre-hashes with SHA-256 to bypass bcrypt's 72-byte limit,
    then applies bcrypt for secure storage.
    Uses hexdigest() to avoid null byte truncation vulnerabilities.
    """
    pwd_hash = hashlib.sha256(
        plain_password.encode('utf-8')
    ).hexdigest()  # Safe: 64-char hex string, no null bytes

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_hash.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Replicates the exact same pre-hashing pipeline as hash_password.
    Both functions must use identical steps or verification will always fail.
    """
    pwd_hash = hashlib.sha256(
        plain_password.encode('utf-8')
    ).hexdigest()  # Must match hash_password exactly

    return bcrypt.checkpw(
        pwd_hash.encode('utf-8'),
        hashed_password.encode('utf-8')
    )

def create_access_token(data: dict) -> str:
    """
    Creates a signed JWT containing the provided data payload.
    Automatically adds an expiry timestamp.
    """
    payload = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.JWT_EXPIRE_MINUTES
    )
    payload.update({"exp": expire})

    token = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    return token


def decode_access_token(token: str) -> dict:
    """
    Validates and decodes a JWT.
    Raises an exception if the token is expired or tampered with.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Token is invalid")

def get_fernet() -> Fernet:
    """
    Initialises the Fernet cipher using your AES key from .env.
    Fernet requires a URL-safe base64-encoded 32-byte key.
    We derive this from your AES_ENCRYPTION_KEY setting.
    """
    settings = get_settings()
    key_bytes = settings.AES_ENCRYPTION_KEY.encode('utf-8')
    key_32 = key_bytes[:32].ljust(32, b'0')
    fernet_key = base64.urlsafe_b64encode(key_32)
    return Fernet(fernet_key)


def create_media_token(content_id: str, user_id: str) -> str:
    """
    Creates an AES-256 encrypted, time-limited token for media access.

    The token contains:
    - content_id: what is being accessed
    - user_id: who is accessing it (for audit trail)
    - expires_at: Unix timestamp after which the token is invalid

    Why store expiry inside the token?
    The server has no session state — it cannot look up when a token
    was issued. Embedding the expiry inside the encrypted payload means
    the token is self-contained and self-validating. This is stateless
    security — no database lookup required.
    """
    settings = get_settings()
    fernet = get_fernet()

    payload = {
        "content_id": content_id,
        "user_id": user_id,
        "expires_at": time.time() + settings.TOKEN_EXPIRY_SECONDS
    }

    payload_bytes = json.dumps(payload).encode('utf-8')
    encrypted_token = fernet.encrypt(payload_bytes)

    return encrypted_token.decode('utf-8')


def validate_media_token(token: str) -> dict:
    """
    Decrypts and validates an AES media token.

    Raises ValueError if:
    - Token cannot be decrypted (tampered or wrong key)
    - Token has expired (past its expires_at timestamp)

    Returns the decrypted payload dict if valid.
    """
    fernet = get_fernet()

    try:
        decrypted_bytes = fernet.decrypt(token.encode('utf-8'))
        payload = json.loads(decrypted_bytes.decode('utf-8'))
    except Exception:
        raise ValueError("Invalid media token")

    if time.time() > payload["expires_at"]:
        raise ValueError("Media token has expired")

    return payload


def generate_hmac_signature(payload: str) -> str:
    """
    Generates an HMAC-SHA256 signature for a given string payload.

    The client calls this before sending a request and includes
    the result in the X-Signature header.
    The server calls this on the received parameters and compares.

    Why use hmac.compare_digest() instead of == for comparison?
    Regular == short-circuits on the first mismatch — a timing
    side-channel attack can measure response times to guess the
    signature one byte at a time. compare_digest() always takes
    the same time regardless of where the mismatch occurs.
    """
    settings = get_settings()
    signature = hmac.new(
        settings.HMAC_SECRET.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return signature


def verify_hmac_signature(payload: str, received_signature: str) -> bool:
    """
    Verifies a received HMAC signature against a recomputed one.
    Uses constant-time comparison to prevent timing attacks.
    """
    expected_signature = generate_hmac_signature(payload)
    return hmac.compare_digest(expected_signature, received_signature)
