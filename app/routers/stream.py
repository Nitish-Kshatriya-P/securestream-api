from fastapi import APIRouter, Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.core.security import (
    decode_access_token,
    create_media_token,
    validate_media_token,
    verify_hmac_signature
)
from typing import Optional
from app.core.logger import log_security_event

router = APIRouter(prefix="/stream", tags=["Streaming"])
security = HTTPBearer()

# Simulated content library
CONTENT_LIBRARY = {
    "episode1": "https://cdn.securestream.internal/medical/episode1.mp4",
    "episode2": "https://cdn.securestream.internal/medical/episode2.mp4",
    "episode3": "https://cdn.securestream.internal/medical/episode3.mp4",
}


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Validates JWT and returns the decoded payload."""
    try:
        payload = decode_access_token(credentials.credentials)
        return payload
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.get("/{content_id}")
def request_stream(
    content_id: str,
    x_signature: Optional[str] = Header(None),
    current_user: dict = Depends(get_current_user)
):
    """
    Protected endpoint — requires valid JWT + valid HMAC signature.

    Flow:
    1. JWT validated by get_current_user dependency
    2. HMAC signature validated against content_id + username
    3. Content existence verified
    4. AES-256 encrypted token generated and returned
    5. Client uses token at /resolve/ to get actual URL

    The client never receives a raw media URL from this endpoint.
    """
    # HMAC validation
    if not x_signature:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing X-Signature header"
        )

    # The signed payload is content_id + username — both must match
    signing_payload = f"{content_id}:{current_user.get('sub')}"

    if not verify_hmac_signature(signing_payload, x_signature):
        log_security_event(
            event_type="HMAC_FAILURE",
            username=current_user.get("sub"),
            source_ip="request",
            endpoint=f"/stream/{content_id}",
            response_code=401,
            details="HMAC signature mismatch — possible parameter tampering"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid request signature"
        )

    # Content existence check
    if content_id not in CONTENT_LIBRARY:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Content not found"
        )

    # Generate AES token (never return raw URL)
    token = create_media_token(
        content_id=content_id,
        user_id=current_user.get("sub")
    )

    log_security_event(
        event_type="STREAM_ACCESS",
        username=current_user.get("sub"),
        source_ip="request",
        endpoint=f"/stream/{content_id}",
        response_code=200,
        details=f"Media token issued for {content_id}"
    )

    return {
        "media_token": token,
        "resolve_url": f"/stream/resolve/{token[:20]}...",
        "expires_in_seconds": 300,
        "message": "Use media_token at /stream/resolve/ to access content"
    }


@router.get("/resolve/{token}")
def resolve_stream(token: str):
    """
    Decrypts and validates a media token, returns the actual URL.

    This is the only endpoint that knows real media URLs.
    Separating token generation from URL resolution means:
    - The /stream/ endpoint never exposes raw URLs
    - Tokens can be validated without a database lookup
    - Expired tokens are rejected here, not at the CDN layer
    """
    try:
        payload = validate_media_token(token)
    except ValueError as e:
        log_security_event(
            event_type="TOKEN_EXPIRED",
            username="unknown",
            source_ip="unknown",
            endpoint=f"/stream/resolve/",
            response_code=401,
            details=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )

    content_id = payload["content_id"]

    if content_id not in CONTENT_LIBRARY:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Content not found"
        )

    return {
        "stream_url": CONTENT_LIBRARY[content_id],
        "content_id": content_id,
        "accessed_by": payload["user_id"],
        "message": "This URL expires — do not cache or share"
    }