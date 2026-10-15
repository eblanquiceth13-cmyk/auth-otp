"""Limitador de peticiones (rate limiting) compartido por toda la aplicación."""
from slowapi import Limiter
from slowapi.util import get_remote_address

# Limita por dirección IP del cliente
limiter = Limiter(key_func=get_remote_address)