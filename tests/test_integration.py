"""Pruebas de integración: recorren la API completa vía HTTP con TestClient."""


def test_registro_exitoso_y_email_duplicado(client, user_data):
    """El primer registro da 201; repetir el mismo email da 409."""
    primera = client.post("/auth/register", json=user_data)
    assert primera.status_code == 201
    cuerpo = primera.json()
    assert "password" not in cuerpo
    assert "password_hash" not in cuerpo

    segunda = client.post("/auth/register", json=user_data)
    assert segunda.status_code == 409


def test_flujo_completo_hasta_el_perfil(client, user_data, sent_otps):
    """register -> login -> verify-otp -> GET /users/profile."""
    assert client.post("/auth/register", json=user_data).status_code == 201

    login = client.post(
        "/auth/login",
        json={"email": user_data["email"], "password": user_data["password"]},
    )
    assert login.status_code == 200
    assert sent_otps, "El login debió 'enviar' un OTP"

    code = sent_otps[-1]["code"]
    verificacion = client.post(
        "/auth/verify-otp", json={"email": user_data["email"], "code": code}
    )
    assert verificacion.status_code == 200
    token = verificacion.json()["access_token"]

    perfil = client.get(
        "/users/profile", headers={"Authorization": f"Bearer {token}"}
    )
    assert perfil.status_code == 200
    assert perfil.json()["email"] == user_data["email"]
    assert "password_hash" not in perfil.json()


def test_ruta_protegida_sin_token_da_401(client):
    """Sin header Authorization, el perfil no es accesible."""
    assert client.get("/users/profile").status_code == 401


def test_token_invalido_da_401(client):
    """Un token inventado tampoco da acceso."""
    headers = {"Authorization": "Bearer token-falso"}
    assert client.get("/users/profile", headers=headers).status_code == 401


def test_logout_revoca_el_token(client, auth_headers):
    """Tras cerrar sesión, el mismo token ya no sirve (401)."""
    assert client.get("/users/profile", headers=auth_headers).status_code == 200

    logout = client.post("/auth/logout", headers=auth_headers)
    assert logout.status_code == 200

    assert client.get("/users/profile", headers=auth_headers).status_code == 401


def test_actualizar_nombre_del_perfil(client, auth_headers):
    """PUT /users/profile cambia el nombre y GET lo refleja."""
    respuesta = client.put(
        "/users/profile", json={"full_name": "Nombre Nuevo"}, headers=auth_headers
    )
    assert respuesta.status_code == 200
    assert respuesta.json()["full_name"] == "Nombre Nuevo"

    perfil = client.get("/users/profile", headers=auth_headers)
    assert perfil.json()["full_name"] == "Nombre Nuevo"


def test_cambiar_contrasena_desde_el_perfil(client, auth_headers, user_data):
    """Tras cambiar la contraseña, la nueva funciona y la anterior ya no."""
    nueva = "ClaveNueva456!"
    respuesta = client.put(
        "/users/profile", json={"password": nueva}, headers=auth_headers
    )
    assert respuesta.status_code == 200

    login_nueva = client.post(
        "/auth/login", json={"email": user_data["email"], "password": nueva}
    )
    assert login_nueva.status_code == 200

    login_vieja = client.post(
        "/auth/login",
        json={"email": user_data["email"], "password": user_data["password"]},
    )
    assert login_vieja.status_code == 401


def test_contrasena_demasiado_larga_da_422_sin_cambios(client, auth_headers):
    """Una contraseña de más de 72 bytes se rechaza y no cambia nada.

    40 letras "ñ" son 40 caracteres (pasan el esquema) pero 80 bytes en UTF-8
    (superan el límite de bcrypt). Debe responder 422, no 500, y el nombre
    enviado en la misma petición no debe guardarse.
    """
    respuesta = client.put(
        "/users/profile",
        json={"full_name": "No Debe Cambiar", "password": "ñ" * 40},
        headers=auth_headers,
    )
    assert respuesta.status_code == 422

    perfil = client.get("/users/profile", headers=auth_headers)
    assert perfil.json()["full_name"] == "Carolina Prueba"
