"""Fixtures compartidos de las pruebas.

Aquí se prepara todo lo necesario para probar sin tocar recursos reales:
- Variables de entorno de prueba (antes de importar la app).
- Una base de datos SQLite en memoria, nueva en cada prueba.
- Un cliente HTTP de prueba que usa esa base de datos.
- Un reemplazo del envío de correo que captura el código OTP.
"""

import os

# Deben definirse ANTES de importar la app: config.py lee estas variables al
# importarse, y SECRET_KEY es obligatoria. Así las pruebas funcionan aunque no
# exista un archivo .env, y nunca tocan la base de datos real (auth.db).
os.environ["SECRET_KEY"] = "clave-solo-para-pruebas-de-32-caracteres-o-mas"
os.environ["DATABASE_URL"] = "sqlite://"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import app.services.otp_service as otp_service  # noqa: E402
from app.database import Base, get_db  # noqa: E402
from app.limiter import limiter  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture()
def db_session():
    """Crea una BD SQLite en memoria con las tablas listas y la entrega.

    ``StaticPool`` hace que toda la prueba use una única conexión; sin eso,
    cada conexión a ``sqlite://`` vería una base de datos distinta y vacía.
    Al terminar, se borran las tablas para que cada prueba empiece limpia.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = testing_session()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture()
def sent_otps(monkeypatch):
    """Reemplaza ``send_otp_email`` para no enviar correos reales.

    Devuelve una lista donde se guarda cada "correo" enviado como
    ``{"email": ..., "code": ...}``, así las pruebas pueden leer el código OTP.
    Se parchea en ``app.services.otp_service`` porque ahí es donde se usa
    (se importó con ``from ... import send_otp_email``).
    """
    capturados = []

    def fake_send_otp_email(to_email, code):
        capturados.append({"email": to_email, "code": code})

    monkeypatch.setattr(otp_service, "send_otp_email", fake_send_otp_email)
    return capturados


@pytest.fixture()
def client(db_session, sent_otps):
    """Cliente HTTP de prueba conectado a la BD de prueba y sin rate limiting.

    El limitador se apaga durante la prueba y se vuelve a encender al
    terminar, para no afectar a otras pruebas que sí lo necesitan (por
    ejemplo, las que verifican el error 429).
    """

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    limiter.enabled = False
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        limiter.enabled = True
        app.dependency_overrides.clear()


@pytest.fixture()
def user_data():
    """Datos de un usuario de prueba válido."""
    return {
        "email": "carolina@example.com",
        "password": "Clave123!",
        "full_name": "Carolina Prueba",
    }


@pytest.fixture()
def auth_headers(client, user_data, sent_otps):
    """Registra, inicia sesión, verifica el OTP y devuelve el header con el JWT."""
    client.post("/auth/register", json=user_data)
    client.post(
        "/auth/login",
        json={"email": user_data["email"], "password": user_data["password"]},
    )
    code = sent_otps[-1]["code"]
    respuesta = client.post(
        "/auth/verify-otp", json={"email": user_data["email"], "code": code}
    )
    token = respuesta.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
