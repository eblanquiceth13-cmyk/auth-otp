"""Endpoints de autenticación: registro, login, OTP, refresh y logout."""
from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["Autenticación"])