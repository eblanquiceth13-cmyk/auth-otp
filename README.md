# Sistema de Autenticación con OTP — FastAPI

API REST de autenticación de dos factores: el usuario inicia sesión con correo y contraseña, recibe un código OTP de 6 dígitos por correo electrónico (válido 15 minutos) y, al verificarlo, obtiene un token JWT para acceder a rutas protegidas. Proyecto del parcial de Desarrollo de Software.

## Equipo

| Integrante | Código | Responsabilidad |
|---|---|---|
| Cantillo Carolina | 20231153656 | Perfil de usuario (`routes/users.py`), pruebas (`tests/`) y documentación (README) |
| Castro Edier | 202311254074 | Base del proyecto (`config.py`, `database.py`, `models.py`, `schemas.py`, `main.py`, `limiter.py`) y despliegue en Render |
| Conde José | 202321256268 | Seguridad y autenticación: hash de contraseñas y JWT (`security.py`), middleware (`middleware.py`) y rutas de autenticación (`routes/auth.py`) |
| Vega José | 202321256198 | Servicios de OTP y correo (`otp_service.py`, `email_service.py`) |

**Cada integrante sustenta individualmente su parte.** Las contribuciones de cada uno quedan registradas en el historial de commits de Git.

## Estado

- Desplegado en Render: https://auth-otp.onrender.com/docs
- Se actualiza automáticamente con cada push a `main`.
- Documentación interactiva (Swagger) disponible en `/docs`.

## Stack tecnológico

- **Backend:** FastAPI (Python 3.12)
- **ORM y base de datos:** SQLAlchemy 2.x con SQLite
- **Validación:** Pydantic v2
- **Contraseñas:** bcrypt
- **Tokens:** PyJWT
- **OTP:** pyotp
- **Rate limiting:** slowapi
- **Correo:** smtplib (SMTP)
- **Pruebas:** pytest + httpx
- **Despliegue:** Render

## Estructura

- `app/main.py`: aplicación principal y registro de routers.
- `app/config.py`: variables de entorno (settings).
- `app/database.py`: engine, sesión y `get_db()`.
- `app/models.py`: modelos SQLAlchemy (`User`, `OTPCode`, `LoginSession`).
- `app/schemas.py`: esquemas Pydantic de entrada y salida.
- `app/security.py`: hash de contraseñas y manejo de JWT.
- `app/middleware.py`: `get_current_user`, valida el token en rutas protegidas.
- `app/limiter.py`: rate limiting con slowapi.
- `app/routes/auth.py`: endpoints de autenticación.
- `app/routes/users.py`: endpoints de perfil.
- `app/services/otp_service.py`: generación y validación de OTP.
- `app/services/email_service.py`: envío de correos.
- `tests/`: pruebas unitarias y de integración (conftest.py, test_unit.py, test_integration.py, test_otp_flow.py, test_otp_service.py).
- `requirements.txt`: dependencias del proyecto.
- `.env.example`: plantilla de variables de entorno.

## Instalación local

1. Clonar el repositorio:
```bash
   git clone https://github.com/eblanquiceth13-cmyk/auth-otp.git
   cd auth-otp
```
2. Crear y activar el entorno virtual:
```bash
   python -m venv venv
   # Linux / macOS
   source venv/bin/activate
   # Windows (PowerShell)
   venv\Scripts\Activate.ps1
```
3. Instalar las dependencias:
```bash
   pip install -r requirements.txt
```
4. Crear el archivo `.env` a partir del ejemplo y completar los valores:
```bash
   cp .env.example .env        # Windows: copy .env.example .env
```

## Cómo correr

```bash
uvicorn app.main:app --reload
```

La API queda en http://127.0.0.1:8000 y la documentación interactiva en http://127.0.0.1:8000/docs.

## Pruebas

```bash
pytest -v
```

Las pruebas usan una base de datos SQLite en memoria (separada de la real), desactivan el rate limiting y reemplazan el envío de correo por una función simulada que captura el código OTP, por lo que **no se envían correos reales**.

## Endpoints

| Método | Ruta | Descripción | Auth |
|---|---|---|---|
| POST | `/auth/register` | Registrar nuevo usuario (409 si el email ya existe) | No |
| POST | `/auth/login` | Validar credenciales y enviar OTP por correo | No |
| POST | `/auth/verify-otp` | Verificar OTP y obtener el JWT | No |
| POST | `/auth/resend-otp` | Reenviar código OTP | No |
| POST | `/auth/refresh` | Refrescar token JWT | Sí |
| POST | `/auth/logout` | Cerrar sesión y revocar el token | Sí |
| GET | `/users/profile` | Ver perfil del usuario | Sí |
| PUT | `/users/profile` | Actualizar nombre y/o contraseña | Sí |

Las rutas protegidas requieren el header `Authorization: Bearer <token>`.

## Variables de entorno

| Variable | Descripción |
|---|---|
| `DATABASE_URL` | URL de la base de datos (ej. `sqlite:///./auth.db`) |
| `SECRET_KEY` | Clave secreta para firmar los JWT (obligatoria) |
| `ALGORITHM` | Algoritmo de firma del JWT (ej. `HS256`) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Duración del token de acceso en minutos (30) |
| `OTP_EXPIRE_MINUTES` | Vigencia del código OTP en minutos (15) |
| `SMTP_HOST` | Servidor SMTP (ej. `smtp.gmail.com`) |
| `SMTP_PORT` | Puerto SMTP (587) |
| `SMTP_USER` | Correo con el que se envían los códigos |
| `SMTP_PASSWORD` | Contraseña o clave de aplicación del correo |
| `SMTP_FROM` | Correo que aparece como remitente |

> Nunca subas el archivo `.env` al repositorio.

## Seguridad

- Contraseñas hasheadas con bcrypt.
- JWT con claim de expiración; cada token queda registrado en `login_sessions`.
- Logout elimina la sesión, por lo que el token queda revocado.
- OTP de 6 dígitos, con vigencia máxima de 15 minutos y de un solo uso.
- Rate limiting en endpoints críticos.
- Las respuestas nunca incluyen `password_hash`.
