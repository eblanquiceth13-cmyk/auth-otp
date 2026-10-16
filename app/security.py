"""Protección de contraseñas con bcrypt y creación y validación de JWT."""

from datetime import datetime, timedelta
from uuid import uuid4

import bcrypt
import jwt

from app.config import settings
from app.models import utcnow


def hash_password(password: str) -> str:
    """Genera un hash bcrypt sin truncar contraseñas mayores a 72 bytes."""
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > 72:
        raise ValueError("La contraseña no puede superar 72 bytes en UTF-8")
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Comprueba una contraseña contra su hash; rechaza hashes inválidos."""
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > 72:
        return False
    try:
        return bcrypt.checkpw(password_bytes, password_hash.encode("utf-8"))
    except (ValueError, UnicodeError):
        return False


def create_access_token(user_id: int) -> tuple[str, datetime]:
    """Crea un JWT único y devuelve su vencimiento en UTC sin zona horaria."""
    now = utcnow().replace(microsecond=0)
    expires_at = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": expires_at,
        # Evita emitir tokens idénticos durante el mismo segundo.
        "jti": uuid4().hex,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return token, expires_at


def decode_access_token(token: str) -> dict:
    """Valida firma y claims; lanza jwt.PyJWTError si el JWT no es válido."""
    payload = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        options={"require": ["sub", "exp", "iat", "jti"]},
    )
    subject = payload.get("sub")
    if not isinstance(subject, str):
        raise jwt.InvalidTokenError("El sujeto debe ser una cadena")
    try:
        user_id = int(subject)
    except ValueError as exc:
        raise jwt.InvalidTokenError("El sujeto no es válido") from exc
    if user_id <= 0 or subject != str(user_id):
        raise jwt.InvalidTokenError("El sujeto no es válido")
    if not isinstance(payload.get("jti"), str) or not payload["jti"]:
        raise jwt.InvalidTokenError("Falta el identificador del token")
    return payload
