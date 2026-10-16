"""Pruebas unitarias de los servicios de OTP y de correo (sin enviar correos reales)."""
import os
from datetime import timedelta
from unittest.mock import MagicMock

# Valores solo para pruebas; no se usan los del .env real
os.environ.setdefault("SECRET_KEY", "clave-exclusiva-de-pruebas-123456789012345")
os.environ.setdefault("DATABASE_URL", "sqlite://")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.database import Base
from app.models import OTPCode, User, utcnow
from app.services import email_service, otp_service


@pytest.fixture
def db():
    """Base de datos SQLite en memoria, nueva para cada prueba."""
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture
def user(db):
    """Usuario de prueba guardado en la base de datos."""
    u = User(email="prueba@example.com", password_hash="hash", full_name="Usuario Prueba")
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def test_generate_code_tiene_6_digitos():
    """El código generado con PyOTP siempre tiene exactamente 6 dígitos numéricos."""
    for _ in range(50):
        code = otp_service.generate_code()
        assert len(code) == 6
        assert code.isdigit()


def test_create_otp_guarda_codigo_con_expiracion(db, user):
    """create_otp guarda el código sin usar y con vencimiento de OTP_EXPIRE_MINUTES."""
    code = otp_service.create_otp(db, user)

    otp = db.query(OTPCode).filter(OTPCode.user_id == user.id).one()
    assert otp.code == code
    assert otp.used is False
    esperado = utcnow() + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)
    assert abs((otp.expires_at - esperado).total_seconds()) < 5


def test_create_otp_invalida_codigos_anteriores(db, user):
    """Al crear un OTP nuevo, el anterior queda marcado como usado y ya no sirve."""
    viejo = otp_service.create_otp(db, user)
    nuevo = otp_service.create_otp(db, user)

    assert db.query(OTPCode).filter(OTPCode.used.is_(False)).count() == 1
    if viejo != nuevo:
        assert otp_service.verify_otp(db, user, viejo) is False
    assert otp_service.verify_otp(db, user, nuevo) is True


def test_verify_otp_valido_solo_una_vez(db, user):
    """Un código correcto valida la primera vez y no se puede reutilizar."""
    code = otp_service.create_otp(db, user)

    assert otp_service.verify_otp(db, user, code) is True
    assert otp_service.verify_otp(db, user, code) is False


def test_verify_otp_codigo_incorrecto(db, user):
    """Un código distinto o mal formado no valida."""
    code = otp_service.create_otp(db, user)
    incorrecto = "000000" if code != "000000" else "111111"

    assert otp_service.verify_otp(db, user, incorrecto) is False
    assert otp_service.verify_otp(db, user, "12ab56") is False
    assert otp_service.verify_otp(db, user, "123") is False


def test_verify_otp_expirado(db, user):
    """Un código vencido no valida aunque sea correcto."""
    code = otp_service.create_otp(db, user)
    otp = db.query(OTPCode).filter(OTPCode.user_id == user.id).one()
    otp.expires_at = utcnow() - timedelta(minutes=1)
    db.commit()

    assert otp_service.verify_otp(db, user, code) is False


def test_create_and_send_otp_envia_el_codigo(db, user, monkeypatch):
    """create_and_send_otp envía al correo del usuario el mismo código que guarda."""
    sender = MagicMock()
    monkeypatch.setattr(otp_service, "send_otp_email", sender)

    otp_service.create_and_send_otp(db, user)

    otp = db.query(OTPCode).filter(OTPCode.user_id == user.id).one()
    sender.assert_called_once_with(user.email, otp.code)


def test_send_otp_email_usa_starttls_y_login(monkeypatch):
    """send_otp_email cifra con STARTTLS, inicia sesión y envía el código en el mensaje."""
    smtp_class = MagicMock()
    server = smtp_class.return_value.__enter__.return_value
    monkeypatch.setattr(email_service.smtplib, "SMTP", smtp_class)

    email_service.send_otp_email("destino@example.com", "482913")

    smtp_class.assert_called_once_with(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10)
    server.starttls.assert_called_once()
    server.login.assert_called_once_with(settings.SMTP_USER, settings.SMTP_PASSWORD)
    mensaje = server.send_message.call_args[0][0]
    assert mensaje["To"] == "destino@example.com"
    # El cuerpo va codificado (base64), así que se decodifica cada parte
    partes = [p.get_payload(decode=True).decode("utf-8") for p in mensaje.walk() if not p.is_multipart()]
    assert len(partes) == 2  # texto plano y HTML
    assert all("482913" in parte for parte in partes)