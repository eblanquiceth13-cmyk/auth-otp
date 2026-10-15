"""
Punto de entrada de la API de autenticación con OTP.
Ejecutar en local: uvicorn app.main:app --reload
"""
import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app import models  # noqa: F401  (registra las tablas en Base)
from app.database import Base, engine
from app.limiter import limiter
from app.routes import auth, users

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("auth-otp")

# Crea las tablas si no existen
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Sistema de Autenticación con OTP",
    description="API con registro, login en dos pasos (OTP por correo), JWT y rutas protegidas.",
    version="1.0.0",
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth.router)
app.include_router(users.router)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Responde 500 sin exponer detalles internos; el error queda solo en el log del servidor."""
    logger.error("Error no controlado en %s %s: %s", request.method, request.url.path, type(exc).__name__)
    return JSONResponse(status_code=500, content={"detail": "Error interno del servidor"})


@app.api_route("/", methods=["GET", "HEAD"], tags=["Estado"])
def health_check():
    """Verifica que la API está en línea (útil para el despliegue)."""
    return {"status": "ok"}