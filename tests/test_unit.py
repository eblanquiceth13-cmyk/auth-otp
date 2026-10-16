"""Pruebas unitarias: prueban piezas aisladas, sin pasar por HTTP."""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from pydantic import ValidationError

from app.config import settings
from app.models import OTPCode, User, utcnow
from app.schemas import OTPVerify, UserRegister
from app.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.services.otp_service import create_otp, verify_otp


@pytest.fixture()
def usuario(db_session):
    """Un usuario guardado en la BD de prueba."""
    user = User(
        email="unit@example.com",
        password_hash=hash_password("Clave123!"),
        full_name="Usuario Unitario",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def ultima_fila_otp(db, user):
    """Devuelve la fila OTPCode más reciente del usuario (para inspeccionarla)."""
    return (
        db.query(OTPCode)
        .filter(OTPCode.user_id == user.id)
        .order_by(OTPCode.id.desc())
        .first()
    )


# --- Contraseñas ------------------------------------------------------------

def test_hash_y_verificacion_de_contrasena():
    """El hash no es la contraseña, y solo verifica con la contraseña correcta."""
    hashed = hash_password("MiClave123!")
    assert hashed != "MiClave123!"
    assert verify_password("MiClave123!", hashed) is True
    assert verify_password("otra-clave", hashed) is False


# --- JWT --------------------------------------------------------------------

def test_crear_y_decodificar_jwt():
    """Un token recién creado se decodifica y trae sus datos y su expiración."""
    token, expires_at = create_access_token(1)
    payload = decode_access_token(token)
    assert payload["sub"] == "1"  # el "sub" guarda el id del usuario
    assert "exp" in payload
    assert "jti" in payload  # identificador único del token
    assert expires_at > utcnow()


def test_jwt_expirado_falla():
    """Un token con fecha de expiración pasada debe ser rechazado.

    Se incluyen todos los datos obligatorios del token (sub, iat, exp, jti)
    para que el único problema sea que ya venció.
    """
    ahora = datetime.now(timezone.utc)
    expirado = jwt.encode(
        {
            "sub": "1",
            "iat": ahora - timedelta(minutes=10),
            "exp": ahora - timedelta(minutes=1),
            "jti": "token-de-prueba",
        },
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(expirado)


def test_jwt_manipulado_falla():
    """Un token alterado (firma inválida) debe ser rechazado."""
    token, _ = create_access_token(1)
    with pytest.raises(jwt.PyJWTError):
        decode_access_token(token + "x")


# --- OTP --------------------------------------------------------------------

def test_otp_tiene_seis_digitos(db_session, usuario):
    """El código generado son exactamente 6 dígitos numéricos."""
    code = create_otp(db_session, usuario)
    assert len(code) == 6
    assert code.isdigit()


def test_otp_valido_se_acepta(db_session, usuario):
    """Control positivo: un OTP vigente y sin usar sí valida."""
    code = create_otp(db_session, usuario)
    assert verify_otp(db_session, usuario, code) is True


def test_codigo_incorrecto_no_valida(db_session, usuario):
    """Un código distinto al generado no valida."""
    code = create_otp(db_session, usuario)
    incorrecto = "000000" if code != "000000" else "111111"
    assert verify_otp(db_session, usuario, incorrecto) is False


def test_otp_expirado_no_valida(db_session, usuario):
    """Un OTP cuya fecha de expiración ya pasó no debe validar."""
    code = create_otp(db_session, usuario)
    fila = ultima_fila_otp(db_session, usuario)
    fila.expires_at = utcnow() - timedelta(minutes=1)
    db_session.commit()
    assert verify_otp(db_session, usuario, code) is False


def test_otp_usado_no_valida(db_session, usuario):
    """Un OTP ya marcado como usado no puede reutilizarse."""
    code = create_otp(db_session, usuario)
    fila = ultima_fila_otp(db_session, usuario)
    fila.used = True
    db_session.commit()
    assert verify_otp(db_session, usuario, code) is False


def test_otp_no_se_puede_reutilizar(db_session, usuario):
    """Tras una verificación exitosa, el mismo código ya no sirve."""
    code = create_otp(db_session, usuario)
    assert verify_otp(db_session, usuario, code) is True
    assert verify_otp(db_session, usuario, code) is False


def test_nuevo_otp_invalida_el_anterior(db_session, usuario):
    """Al pedir un código nuevo, el anterior queda marcado como usado."""
    create_otp(db_session, usuario)
    primera = ultima_fila_otp(db_session, usuario)
    create_otp(db_session, usuario)
    segunda = ultima_fila_otp(db_session, usuario)

    db_session.refresh(primera)
    assert primera.used is True
    assert segunda.used is False


# --- Esquemas ---------------------------------------------------------------

def test_esquemas_validan_datos():
    """Pydantic rechaza correos inválidos, contraseñas cortas y campos faltantes."""
    valido = UserRegister(
        email="ok@example.com", password="Clave123!", full_name="Ok Usuario"
    )
    assert valido.email == "ok@example.com"

    with pytest.raises(ValidationError):  # correo mal escrito
        UserRegister(
            email="no-es-un-correo", password="Clave123!", full_name="Ok Usuario"
        )

    with pytest.raises(ValidationError):  # contraseña de menos de 8 caracteres
        UserRegister(email="ok@example.com", password="corta", full_name="Ok Usuario")

    with pytest.raises(ValidationError):  # falta el código
        OTPVerify(email="ok@example.com")

    with pytest.raises(ValidationError):  # el código debe ser de 6 dígitos
        OTPVerify(email="ok@example.com", code="12ab")
