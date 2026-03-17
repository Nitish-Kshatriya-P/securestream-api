from fastapi import APIRouter, HTTPException, Request, status
from app.models.schemas import LoginRequest, TokenResponse
from app.core.security import verify_password, create_access_token, hash_password
from app.core.logger import log_security_event

router = APIRouter(prefix="/auth", tags=["Authentication"])

FAKE_USERS_DB = {
    "dr.smith": {
        "username": "dr.smith",
        "hashed_password": hash_password("securepass123"),
        "role": "doctor"
    }
}


@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest, req: Request):
    """
    Authenticates a user and returns a signed JWT.
    Every outcome — success or failure — is logged as a security event.
    """
    source_ip = req.client.host
    user = FAKE_USERS_DB.get(request.username)

    if not user or not verify_password(request.password,
                                       user["hashed_password"]):
        # Log the failure BEFORE raising the exception
        log_security_event(
            event_type="AUTH_FAILURE",
            username=request.username,
            source_ip=source_ip,
            endpoint="/auth/login",
            response_code=401,
            details="Invalid credentials"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    log_security_event(
        event_type="AUTH_SUCCESS",
        username=request.username,
        source_ip=source_ip,
        endpoint="/auth/login",
        response_code=200,
        details="JWT issued"
    )

    token = create_access_token(data={
        "sub": user["username"],
        "role": user["role"]
    })

    return TokenResponse(access_token=token)