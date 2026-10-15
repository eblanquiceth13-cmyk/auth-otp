"""Endpoints del perfil de usuario (requieren autenticación)."""
from fastapi import APIRouter

router = APIRouter(prefix="/users", tags=["Usuarios"])