"""Esquemas Pydantic: validan los datos de entrada y definen las respuestas de la API."""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# ---------- Entradas ----------

class UserRegister(BaseModel):
    """Datos para registrar un usuario nuevo."""

    email: EmailStr
    # bcrypt solo admite hasta 72 bytes, por eso se limita la longitud
    password: str = Field(min_length=8, max_length=72)
    full_name: str = Field(min_length=2, max_length=150)

    model_config = ConfigDict(json_schema_extra={
        "examples": [{"email": "ana@example.com", "password": "Segura123*", "full_name": "Ana Pérez"}]
    })


class UserLogin(BaseModel):
    """Credenciales para iniciar sesión (paso 1; después se envía el OTP)."""

    email: EmailStr
    password: str

    model_config = ConfigDict(json_schema_extra={
        "examples": [{"email": "ana@example.com", "password": "Segura123*"}]
    })


class OTPVerify(BaseModel):
    """Código OTP recibido por correo (paso 2 del login)."""

    email: EmailStr
    code: str = Field(pattern=r"^\d{6}$")

    model_config = ConfigDict(json_schema_extra={
        "examples": [{"email": "ana@example.com", "code": "482913"}]
    })


class OTPResend(BaseModel):
    """Solicitud para reenviar el código OTP."""

    email: EmailStr

    model_config = ConfigDict(json_schema_extra={
        "examples": [{"email": "ana@example.com"}]
    })


class UserUpdate(BaseModel):
    """Campos editables del perfil. Todos son opcionales."""

    full_name: Optional[str] = Field(default=None, min_length=2, max_length=150)
    password: Optional[str] = Field(default=None, min_length=8, max_length=72)

    model_config = ConfigDict(json_schema_extra={
        "examples": [{"full_name": "Ana María Pérez"}]
    })


# ---------- Respuestas ----------

class UserResponse(BaseModel):
    """Datos públicos del usuario (nunca incluye el hash de la contraseña)."""

    id: int
    email: str
    full_name: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True, json_schema_extra={
        "examples": [{
            "id": 1,
            "email": "ana@example.com",
            "full_name": "Ana Pérez",
            "created_at": "2026-10-15T18:00:00",
            "updated_at": "2026-10-15T18:00:00",
        }]
    })


class TokenResponse(BaseModel):
    """Token JWT entregado tras verificar el OTP."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int  # segundos

    model_config = ConfigDict(json_schema_extra={
        "examples": [{"access_token": "eyJhbGciOiJIUzI1NiIs...", "token_type": "bearer", "expires_in": 1800}]
    })


class MessageResponse(BaseModel):
    """Respuesta simple con un mensaje."""

    message: str