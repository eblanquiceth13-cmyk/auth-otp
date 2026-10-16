"""Rutas de usuario: consulta y actualización del perfil.

Ambas rutas están protegidas: dependen de ``get_current_user``, que valida el
token JWT (y que la sesión no haya sido revocada con logout). Si el token es
inválido, FastAPI responde 401 antes de ejecutar el código de la ruta.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.middleware import get_current_user
from app.models import User, utcnow
from app.schemas import UserResponse, UserUpdate
from app.security import hash_password

router = APIRouter(prefix="/users", tags=["Usuarios"])


@router.get("/profile", response_model=UserResponse)
def get_profile(current_user: User = Depends(get_current_user)) -> User:
    """Devuelve el perfil del usuario autenticado.

    No recibe parámetros: el usuario se identifica por el token JWT.
    ``response_model=UserResponse`` filtra la salida, así que campos
    sensibles como ``password_hash`` nunca se exponen.
    """
    return current_user


@router.put("/profile", response_model=UserResponse)
def update_profile(
    payload: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    """Actualiza el nombre y/o la contraseña del usuario autenticado.

    Ambos campos son opcionales (actualización parcial):
    - ``full_name``: se reemplaza si viene en la petición.
    - ``password``: se hashea con bcrypt antes de guardarse; la contraseña
      en texto plano nunca se almacena.
    Siempre se actualiza ``updated_at``.

    Primero se valida y hashea la contraseña, y solo después se modifica el
    usuario: así, si la contraseña es inválida, no queda ningún cambio a medias.
    """
    nuevo_hash = None
    if payload.password is not None:
        try:
            nuevo_hash = hash_password(payload.password)
        except ValueError as exc:
            # bcrypt solo admite 72 bytes: con tildes o ñ se puede pasar
            # aunque el esquema (que cuenta caracteres) la haya aceptado.
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    if payload.full_name is not None:
        current_user.full_name = payload.full_name

    if nuevo_hash is not None:
        current_user.password_hash = nuevo_hash

    current_user.updated_at = utcnow()
    db.commit()
    db.refresh(current_user)
    return current_user