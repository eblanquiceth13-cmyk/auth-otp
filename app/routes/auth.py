"""Registro, login con OTP, renovación del JWT y cierre de sesión."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.limiter import limiter
from app.middleware import get_current_session, unauthorized
from app.models import LoginSession, OTPCode, User, utcnow
from app.schemas import (
    MessageResponse,
    OTPResend,
    OTPVerify,
    TokenResponse,
    UserLogin,
    UserRegister,
    UserResponse,
)
from app.security import create_access_token, hash_password, verify_password


router = APIRouter(prefix="/auth", tags=["Autenticación"])

# Ejecuta bcrypt también si el correo no existe para reducir diferencias de tiempo.
_DUMMY_PASSWORD_HASH = hash_password("clave-interna-de-comparacion")


@router.post(
    "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
@limiter.limit("5/minute")
def register(
    request: Request,
    data: UserRegister,
    db: Session = Depends(get_db),
):
    """Registra un usuario sin guardar ni devolver su contraseña en claro."""
    email = str(data.email)
    if db.query(User).filter(User.email == email).first() is not None:
        raise HTTPException(status_code=409, detail="El correo ya está registrado")
    try:
        password_hash = hash_password(data.password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    user = User(
        email=email,
        password_hash=password_hash,
        full_name=data.full_name,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Otra solicitud pudo registrar el mismo correo entre la consulta y el commit.
        if db.query(User).filter(User.email == email).first() is not None:
            raise HTTPException(
                status_code=409, detail="El correo ya está registrado"
            ) from None
        raise
    db.refresh(user)
    return user


@router.post("/login", response_model=MessageResponse)
@limiter.limit("5/minute")
def login(
    request: Request,
    data: UserLogin,
    db: Session = Depends(get_db),
):
    """Valida credenciales y solicita el OTP; todavía no entrega un JWT."""
    user = db.query(User).filter(User.email == str(data.email)).first()
    password_hash = user.password_hash if user is not None else _DUMMY_PASSWORD_HASH
    password_is_valid = verify_password(data.password, password_hash)
    if user is None or not password_is_valid:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    # Se importa aquí para permitir el arranque mientras Vega completa su módulo.
    # Sin esta función, un login correcto falla; nunca se simula el envío del OTP.
    from app.services.otp_service import create_and_send_otp

    create_and_send_otp(db, user)
    return MessageResponse(message="Código OTP enviado al correo")


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    current_session: LoginSession = Depends(get_current_session),
    db: Session = Depends(get_db),
):
    """Sustituye una sesión vigente por otra y revoca el token anterior."""
    user_id = current_session.user_id
    old_session_id = current_session.id
    old_token = current_session.token
    token, expires_at = create_access_token(user_id)
    try:
        # Borrado condicional: solo una solicitud puede renovar esta sesión.
        result = db.execute(
            delete(LoginSession)
            .where(
                LoginSession.id == old_session_id,
                LoginSession.token == old_token,
                LoginSession.expires_at > utcnow(),
            )
            .execution_options(synchronize_session="fetch")
        )
        if result.rowcount != 1:
            raise unauthorized()
        db.add(LoginSession(user_id=user_id, token=token, expires_at=expires_at))
        # El borrado y la creación se confirman o se revierten juntos.
        db.commit()
    except Exception:
        db.rollback()
        raise
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout", response_model=MessageResponse)
def logout(
    current_session: LoginSession = Depends(get_current_session),
    db: Session = Depends(get_db),
):
    """Elimina exclusivamente la sesión del token presentado por el cliente."""
    try:
        db.execute(
            delete(LoginSession)
            .where(
                LoginSession.id == current_session.id,
                LoginSession.token == current_session.token,
            )
            .execution_options(synchronize_session="fetch")
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return MessageResponse(message="Sesión cerrada correctamente")


@router.post("/verify-otp", response_model=TokenResponse)
@limiter.limit("5/minute")
def verify_otp_endpoint(
    request: Request,
    data: OTPVerify,
    db: Session = Depends(get_db),
):
    """Consume el OTP una sola vez y guarda la sesión antes de devolver el JWT."""
    from app.services.otp_service import verify_otp

    user = db.query(User).filter(User.email == str(data.email)).first()
    if user is None or not verify_otp(db, user, data.code):
        raise HTTPException(status_code=401, detail="Código OTP inválido o expirado")

    token, expires_at = create_access_token(user.id)
    try:
        db.add(LoginSession(user_id=user.id, token=token, expires_at=expires_at))
        db.commit()
    except Exception:
        db.rollback()
        raise
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/resend-otp", response_model=MessageResponse)
@limiter.limit("5/minute")
def resend_otp_endpoint(
    request: Request,
    data: OTPResend,
    db: Session = Depends(get_db),
):
    """Reenvía solo para un login pendiente e invalida el código anterior."""
    from app.services.otp_service import create_and_send_otp

    message = MessageResponse(
        message="Si existe un inicio de sesión pendiente, recibirás un nuevo código"
    )
    user = db.query(User).filter(User.email == str(data.email)).first()
    if user is None:
        return message
    pending = db.query(OTPCode).filter(
        OTPCode.user_id == user.id,
        OTPCode.used.is_(False),
        OTPCode.expires_at > utcnow(),
    ).first()
    if pending is None:
        return message
    create_and_send_otp(db, user)
    return message
