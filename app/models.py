"""Modelos SQLAlchemy: tablas users, otp_codes y login_sessions."""
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow():
    """
    Fecha y hora actual en UTC, sin zona horaria.
    SQLite no guarda la zona horaria, así que todas las comparaciones
    de fechas del proyecto deben usar esta función.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    """Usuario registrado en el sistema."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(150), nullable=False)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    otp_codes = relationship("OTPCode", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("LoginSession", back_populates="user", cascade="all, delete-orphan")


class OTPCode(Base):
    """Código OTP de 6 dígitos con fecha de expiración."""

    __tablename__ = "otp_codes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    code = Column(String(6), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)

    user = relationship("User", back_populates="otp_codes")


class LoginSession(Base):
    """
    Sesión activa. Guarda el JWT emitido; en el logout se borra la fila,
    y el middleware rechaza cualquier token que ya no esté en esta tabla.
    """

    __tablename__ = "login_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token = Column(String(500), unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=utcnow)

    user = relationship("User", back_populates="sessions")