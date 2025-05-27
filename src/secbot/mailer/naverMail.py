import os
import ssl
import smtplib
import logging
from email.message import EmailMessage
from datetime import datetime
import unicodedata

# Logger setup
logger = logging.getLogger(__name__)

# Load SMTP configuration from environment
SMTP_HOST = os.getenv("SEC_BOT_SMTP_HOST", "smtp.naver.com")
SMTP_PORT = int(os.getenv("SEC_BOT_SMTP_PORT", 465))
SMTP_USER = os.getenv("SEC_BOT_SMTP_USER")
SMTP_APP_PASSWORD = os.getenv("SEC_BOT_SMTP_APP_PASSWORD", "")

def _get_auth_credentials():
    """
    Returns (username, password) for SMTP authentication.
    """
    if not SMTP_USER:
        raise RuntimeError("SEC_BOT_SMTP_USER is not set")
    if not SMTP_APP_PASSWORD:
        raise RuntimeError("SEC_BOT_SMTP_APP_PASSWORD is not set")
    return SMTP_USER, SMTP_APP_PASSWORD

def send(msg: EmailMessage) -> None:
    """
    Open an SMTP connection and send the EmailMessage.
    """
    user, password = _get_auth_credentials()
    # Normalize password to NFC and replace special hyphens
    password = unicodedata.normalize('NFKC', password)
    # Replace non-breaking hyphens (U+2011) and hyphen characters (U+2010) with ASCII hyphen
    password = password.replace('\u2011', '-').replace('\u2010', '-')

    # Determine SSL vs STARTTLS
    port = 465 if SMTP_PORT == 465 else SMTP_PORT
    if port == 465:
        context = ssl.create_default_context()
        logger.debug("Connecting to %s:%d via SSL", SMTP_HOST, port)
        server = smtplib.SMTP_SSL(SMTP_HOST, port, context=context)
        server.ehlo()
    else:
        logger.debug("Connecting to %s:%d via STARTTLS", SMTP_HOST, port)
        server = smtplib.SMTP(SMTP_HOST, port, timeout=30)
        server.ehlo()
        server.starttls(context=ssl.create_default_context())
        server.ehlo()

    try:
        server.login(user, password)
        server.send_message(msg)
        logger.info("Email sent to %s", msg["To"])
    finally:
        server.quit()

def send_security_news(news_items: list, subject: str) -> None:
    """
    Send a security news digest email.
    """
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = os.getenv("SEC_BOT_MAIL_TO")
    msg.set_content("\n\n".join([f"- {n.title}: {n.link}" for n in news_items]))

    send(msg)

def send_advisories(advisory_list: list, subject: str) -> None:
    """
    Send advisories.
    """
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = os.getenv("SEC_BOT_MAIL_TO")
    msg.set_content("\n\n".join([f"- {a.title}: {a.link}" for a in advisory_list]))

    send(msg)

def send_ioc(ioc_list: list, subject: str) -> None:
    """
    Send IOC list.
    """
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = os.getenv("SEC_BOT_MAIL_TO")
    msg.set_content("\n\n".join([f"- {ioc}" for ioc in ioc_list]))

    send(msg)

def send_digest(news: list, advisories: list, iocs: list) -> None:
    """
    Send the combined security digest email.
    """
    date_str = datetime.now().strftime("%Y-%m-%d")
    subject = f"[SecBot] Security Digest {date_str}"

    # Compose body with sections
    lines = ["Security News:"]
    lines += [f"• {n.title} ({n.link})" for n in news]
    lines += ["", "Advisories:"]
    lines += [f"• {a.title} ({a.link})" for a in advisories]
    lines += ["", "IOCs:"]
    lines += [f"• {ioc}" for ioc in iocs]

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = os.getenv("SEC_BOT_MAIL_TO")
    msg.set_content("\n".join(lines))

    send(msg)