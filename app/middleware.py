"""Dependencias de FastAPI para autenticar sesiones y obtener al usuario."""

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import LoginSession, User, utcnow
from app.security import decode_access_token


bearer_scheme = HTTPBearer(auto_error=False)


def unauthorized() -> HTTPException:
    """Construye el mismo error 401 para credenciales ausentes o inválidas."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No autenticado",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_session(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> LoginSession:
    """Exige un JWT válido con una sesión vigente y un usuario existente."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized()
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        raise unauthorized() from None

    session = (
        db.query(LoginSession)
        .filter(
            LoginSession.token == token,
            LoginSession.user_id == int(payload["sub"]),
            LoginSession.expires_at > utcnow(),
        )
        .first()
    )
    if session is None or db.get(User, session.user_id) is None:
        raise unauthorized()
    return session


def get_current_user(
    session: LoginSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> User:
    """Obtiene el usuario de la sesión autenticada para una ruta protegida."""
    user = db.get(User, session.user_id)
    if user is None:
        raise unauthorized()
    return user
