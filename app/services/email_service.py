"""Servicio de envío de correos con el código OTP usando smtplib."""
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.config import settings

logger = logging.getLogger("auth-otp.email")


def send_otp_email(to_email: str, code: str) -> None:
    """
    Envía el código OTP al correo del usuario, en texto plano y HTML.
    Se conecta al servidor SMTP con STARTTLS y se autentica con la contraseña de aplicación.
    Por seguridad, nunca escribe en los logs el código ni las credenciales.
    """
    minutes = settings.OTP_EXPIRE_MINUTES

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Tu código de verificación"
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to_email

    text = (
        f"Tu código de verificación es: {code}\n"
        f"Vence en {minutes} minutos.\n"
        "Si no intentaste iniciar sesión, ignora este correo."
    )
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 420px; margin: auto;">
      <h2>Código de verificación</h2>
      <p>Usa este código para completar tu inicio de sesión:</p>
      <p style="font-size: 32px; font-weight: bold; letter-spacing: 6px;">{code}</p>
      <p>Vence en {minutes} minutos.</p>
      <p style="color: #777;">Si no intentaste iniciar sesión, ignora este correo.</p>
    </div>
    """

    msg.attach(MIMEText(text, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
            server.starttls()  # cifra la conexión antes de enviar la contraseña
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.send_message(msg)
        logger.info("Correo OTP enviado")
    except (smtplib.SMTPException, OSError) as exc:
        # Solo se registra el tipo de error, sin datos sensibles
        logger.error("No se pudo enviar el correo OTP: %s", type(exc).__name__)
        raise