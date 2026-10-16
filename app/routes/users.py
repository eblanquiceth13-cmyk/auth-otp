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

@router.get("/profile", response_model=UserResponse)
def get_profile(current_user: User = Depends(get_current_user)) -> User:
    """Devuelve el perfil del usuario autenticado.

    No recibe parámetros: el usuario se identifica por el token JWT.
    ``response_model=UserResponse`` filtra la salida, así que campos sensibles
    como ``password_hash`` nunca se exponen.
    """
    return current_user


@router.put("/profile", response_model=UserResponse)
def update_profile(
    datos: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    """Actualiza el nombre y/o la contraseña del usuario autenticado.

    Ambos campos son opcionales, pero se debe enviar al menos uno. Si llega
    ``password`` nunca se guarda en texto plano: se guarda su hash (bcrypt).

    Respuestas: 200 con el perfil actualizado, 400 si no se envió ningún
    campo, 401 si el token no es válido y 422 si la contraseña supera los
    72 bytes que admite bcrypt.
    """
    if datos.full_name is None and datos.password is None:
        raise HTTPException(
            status_code=400,
            detail="Debes enviar full_name y/o password para actualizar.",
        )

    # Se vuelve a leer el usuario con la sesión de esta petición (FastAPI
    # reutiliza la misma sesión de get_db, así que es el mismo objeto).
    usuario = db.get(User, current_user.id)

    if datos.full_name is not None:
        usuario.full_name = datos.full_name
    if datos.password is not None:
        try:
            usuario.password_hash = hash_password(datos.password)
        except ValueError as exc:
            # bcrypt limita la contraseña a 72 bytes (ojo con tildes y emojis)
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    usuario.updated_at = utcnow()
    db.commit()
    db.refresh(usuario)
    return usuario
