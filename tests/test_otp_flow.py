"""Pruebas de endpoints OTP sin correos reales ni acceso a la base de producción."""
import os
from datetime import timedelta
from unittest.mock import Mock

os.environ['SECRET_KEY'] = 'clave-exclusiva-de-pruebas-123456789012345'
os.environ['DATABASE_URL'] = 'sqlite://'

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Query, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.limiter import limiter
from app.models import OTPCode, LoginSession, User, utcnow
from app.services import otp_service


@pytest.fixture
def api(monkeypatch):
    """Aísla SQLite y captura los códigos enviados por el servicio real."""
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    def database():
        with sessions() as db:
            yield db
    app.dependency_overrides[get_db] = database
    limiter.reset()
    sender = Mock()
    monkeypatch.setattr(otp_service, 'send_otp_email', sender)
    codes = iter(['123456', '654321', '345678', '876543'])
    monkeypatch.setattr(otp_service, 'generate_code', lambda: next(codes))
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client, sessions, sender
    app.dependency_overrides.clear()
    limiter.reset()
    engine.dispose()


def start(client):
    """Registra y autentica la contraseña para generar el primer OTP."""
    data = {'email': 'ana@example.com', 'password': 'Segura123*', 'full_name': 'Ana Pérez'}
    assert client.post('/auth/register', json=data).status_code == 201
    assert client.post('/auth/login', json=data).status_code == 200


def test_complete_flow(api):
    """Recorre registro, login, reenvío, verificación, refresh y logout."""
    client, sessions, sender = api
    start(client)
    assert sender.call_args.args == ('ana@example.com', '123456')
    with sessions() as db:
        assert db.query(LoginSession).count() == 0
    assert client.post('/auth/resend-otp', json={'email': 'ana@example.com'}).status_code == 200
    assert sender.call_args.args[1] == '654321'
    assert client.post('/auth/verify-otp', json={'email': 'ana@example.com', 'code': '123456'}).status_code == 401
    response = client.post('/auth/verify-otp', json={'email': 'ana@example.com', 'code': '654321'})
    assert response.status_code == 200, response.text
    token = response.json()['access_token']
    with sessions() as db:
        assert db.query(LoginSession).one().token == token
    assert client.post('/auth/verify-otp', json={'email': 'ana@example.com', 'code': '654321'}).status_code == 401
    response = client.post('/auth/refresh', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    new_token = response.json()['access_token']
    assert new_token != token
    assert client.post('/auth/logout', headers={'Authorization': f'Bearer {token}'}).status_code == 401
    assert client.post('/auth/logout', headers={'Authorization': f'Bearer {new_token}'}).status_code == 200
    assert client.post('/auth/refresh', headers={'Authorization': f'Bearer {new_token}'}).status_code == 401


def test_expiry_and_unicode_code(api):
    """Rechaza OTP vencido y dígitos Unicode sin producir un error 500."""
    client, sessions, _ = api
    start(client)
    assert client.post('/auth/verify-otp', json={'email': 'ana@example.com', 'code': '１２３４５６'}).status_code in (401, 422)
    with sessions() as db:
        db.query(OTPCode).update({'expires_at': utcnow() - timedelta(seconds=1)})
        db.commit()
    assert client.post('/auth/verify-otp', json={'email': 'ana@example.com', 'code': '123456'}).status_code == 401
    with sessions() as db:
        assert db.query(LoginSession).count() == 0


def test_resend_requires_pending_login(api):
    """Un correo desconocido o sin login pendiente no provoca ningún envío."""
    client, _, sender = api
    data = {'email': 'ana@example.com', 'password': 'Segura123*', 'full_name': 'Ana'}
    assert client.post('/auth/register', json=data).status_code == 201
    first = client.post('/auth/resend-otp', json={'email': 'ana@example.com'})
    second = client.post('/auth/resend-otp', json={'email': 'otro@example.com'})
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    sender.assert_not_called()


@pytest.mark.parametrize('path', ['/auth/verify-otp', '/auth/resend-otp'])
def test_limits(api, path):
    """La sexta solicitud recibe 429 en los dos endpoints nuevos."""
    client, _, _ = api
    data = {'email': 'otro@example.com', 'code': '123456'}
    for _ in range(5):
        assert client.post(path, json=data).status_code != 429
    assert client.post(path, json=data).status_code == 429


def test_swagger_routes(api):
    """OpenAPI registra los endpoints OTP y sus modelos de respuesta."""
    client, _, _ = api
    paths = client.get('/openapi.json').json()['paths']
    assert paths['/auth/verify-otp']['post']['responses']['200']['content']['application/json']['schema']['$ref'].endswith('/TokenResponse')
    assert '/auth/resend-otp' in paths

def test_otp_cannot_be_consumed_twice_with_interleaved_requests(api, monkeypatch):
    """Reproduce dos solicitudes que leen el mismo OTP antes de marcarlo usado."""
    client, sessions, _ = api
    start(client)
    with sessions() as db:
        user = db.query(User).one()
        user_id = user.id
        code = otp_service.create_otp(db, user)
    original_first = Query.first
    entered = False
    results = []
    with sessions() as first_db, sessions() as second_db:
        first_user = first_db.get(User, user_id)
        second_user = second_db.get(User, user_id)

        def first_with_interleaving(query):
            nonlocal entered
            row = original_first(query)
            if not entered:
                entered = True
                results.append(otp_service.verify_otp(second_db, second_user, code))
            return row

        monkeypatch.setattr(Query, "first", first_with_interleaving)
        results.append(otp_service.verify_otp(first_db, first_user, code))
    assert results.count(True) == 1, f"El mismo OTP fue aceptado {results.count(True)} veces"
