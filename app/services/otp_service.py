"""Servicio OTP: genera, guarda, verifica y envía códigos de un solo uso."""
import secrets
from datetime import timedelta

import pyotp
from sqlalchemy.orm import Session

from app.config import settings
from app.models import OTPCode, User, utcnow
from app.services.email_service import send_otp_email


def generate_code() -> str:
    """
    Genera un código de 6 dígitos con PyOTP.
    Cada vez se usa un secreto aleatorio nuevo, así que el código no se puede predecir.
    La expiración no depende de PyOTP: se controla con expires_at en la base de datos.
    """
    secret = pyotp.random_base32()
    return pyotp.TOTP(secret, digits=6).now()


def create_otp(db: Session, user: User) -> str:
    """
    Crea un OTP nuevo para el usuario, válido por OTP_EXPIRE_MINUTES.
    Antes invalida los códigos anteriores sin usar, para que solo sirva el último.
    """
    db.query(OTPCode).filter(
        OTPCode.user_id == user.id, OTPCode.used.is_(False)
    ).update({OTPCode.used: True}, synchronize_session=False)

    code = generate_code()
    otp = OTPCode(
        user_id=user.id,
        code=code,
        expires_at=utcnow() + timedelta(minutes=settings.OTP_EXPIRE_MINUTES),
    )
    db.add(otp)
    db.commit()
    return code


def verify_otp(db: Session, user: User, code: str) -> bool:
    """
    Verifica el código del usuario: debe existir, no estar usado ni expirado y coincidir.
    Si es válido lo marca como usado, así no se puede reutilizar.
    """
    otp = (
        db.query(OTPCode)
        .filter(OTPCode.user_id == user.id, OTPCode.used.is_(False))
        .order_by(OTPCode.id.desc())
        .first()
    )
    if otp is None or otp.expires_at < utcnow():
        return False
    # compare_digest compara en tiempo constante (evita ataques de tiempo)
    if not secrets.compare_digest(otp.code, code):
        return False

    otp.used = True
    db.commit()
    return True


def create_and_send_otp(db: Session, user: User) -> None:
    """Crea un OTP nuevo y lo envía al correo del usuario. Lo usa /auth/login."""
    code = create_otp(db, user)
    send_otp_email(user.email, code)