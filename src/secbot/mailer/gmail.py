"""
secbot.mailer.gmail
~~~~~~~~~~~~~~~~~~~

Utility helpers for sending e‑mails through **Gmail** (SMTP over TLS) with
either an **App Password** or **XOAUTH2** access token.

Why two modes?
--------------
* Google는 2024년부터 일반 비밀번호 인증(“less secure apps”)을 완전히 중단,
  대신 **App Password**(2‑Step Enabled 계정 전용) 혹은 OAuth 2.0
  XOAUTH2 인증 둘 중 하나를 사용해야 한다.
* 조직용 Google Workspaces에서는 서비스 계정 + delegated access
  권한으로도 토큰을 발급받을 수 있지만, 여기서는 **이미 발급된
  액세스 토큰 문자열**을 환경변수로 전달받아 사용하는 단순 모델을 채택.

Public API
----------
send_digest(news, advisories, iocs, *, subject=None) -> None
    • 보안뉴스/공지/IOC 데이터를 꾸며서 메일 본문을 생성하고 발송.

send(msg: EmailMessage) -> None
    • 아무 `EmailMessage`나 Gmail SMTP로 전송.
"""

from __future__ import annotations

import datetime as _dt
import logging
import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Iterable, List

import io
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# 환경 변수 설정
# -----------------------------------------------------------------------------
SMTP_HOST = os.getenv("SEC_BOT_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SEC_BOT_SMTP_PORT", "465"))
SMTP_USER = os.getenv("SEC_BOT_SMTP_USER")  # full address
SMTP_APP_PASSWORD = os.getenv("SEC_BOT_SMTP_APP_PASSWORD")  # 16‑digit
SMTP_XOAUTH2_TOKEN = os.getenv("SEC_BOT_SMTP_XOAUTH2")  # Bearer token
MAIL_TO: List[str] = [
    addr.strip()
    for addr in os.getenv("SEC_BOT_MAIL_TO", SMTP_USER or "").split(",")
    if addr.strip()
]

if not SMTP_USER or not MAIL_TO:
    logger.warning(
        "Gmail sender or recipient not configured. Set SEC_BOT_SMTP_USER and "
        "SEC_BOT_MAIL_TO in the environment."
    )

# -----------------------------------------------------------------------------
# 내부 유틸
# -----------------------------------------------------------------------------


def _build_body(
    news: Iterable,
    advisories: Iterable,
    iocs: dict,
) -> str:
    """Create plain‑text digest body from collected artefacts."""
    lines: List[str] = []

    # Headline
    lines.append(f"🛡️  관제 공화국 SecBot – {_dt.date.today():%Y-%m-%d}")
    lines.append("=" * 50)

    # News section
    lines.append("\n[ 보안 뉴스 ]")
    lines.extend(item.to_md() if hasattr(item, "to_md") else f"- {item}" for item in news)

    # Advisory section
    lines.append("\n[ KISA 취약점 공지 ]")
    lines.extend(
        adv.to_md() if hasattr(adv, "to_md") else f"- {adv}" for adv in advisories
    )

    # Malicious IOC details
    lines.append("\n[ ASEC 데일리 IOC ]")
    # Sort IOC lists for display
    ips = sorted(iocs.get("ip", []))
    hashes = sorted(iocs.get("hash", []))
    urls = sorted(iocs.get("url", []))

    lines.append(f"- IP ({len(ips)}):")
    for ip in ips:
        lines.append(f"    - {ip}")

    lines.append(f"- HASH ({len(hashes)}):")
    for h in hashes:
        lines.append(f"    - {h}")

    lines.append(f"- URL ({len(urls)}):")
    for u in urls:
        lines.append(f"    - {u}")

    # Footer
    lines.append("\n— Sent automatically by SecBot\n")
    return "\n".join(lines)


def _get_auth_credentials() -> tuple[str, str | None]:
    """
    Decide whether to use APP PASSWORD vs XOAUTH2.

    Returns
    -------
    tuple[user, auth_string_or_password]
        * If XOAUTH2 token is provided, returns the user and pre‑built XOAUTH2
          `AUTH` string (base64).
        * Else, returns the user and app password.
    """
    if SMTP_XOAUTH2_TOKEN:
        import base64

        auth_string = f"user={SMTP_USER}\1auth=Bearer {SMTP_XOAUTH2_TOKEN}\1\1"
        xoauth2_b64 = base64.b64encode(auth_string.encode()).decode()
        logger.debug("Using XOAUTH2 token for Gmail SMTP auth")
        return SMTP_USER, xoauth2_b64

    if SMTP_APP_PASSWORD:
        logger.debug("Using App Password for Gmail SMTP auth")
        return SMTP_USER, SMTP_APP_PASSWORD

    raise RuntimeError(
        "Neither SEC_BOT_SMTP_APP_PASSWORD nor SEC_BOT_SMTP_XOAUTH2 provided"
    )


# -----------------------------------------------------------------------------
# PDF Report Helper
# -----------------------------------------------------------------------------

def generate_pdf_report(news, advisories, iocs) -> bytes:
    """
    Build a PDF report from security news, advisories, and IOCs.
    Returns the raw PDF bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title = f"Daily Security Report – {_dt.date.today():%Y-%m-%d}"
    story.append(Paragraph(title, styles["Title"]))
    story.append(Spacer(1, 12))

    # News section
    story.append(Paragraph("Security News", styles["Heading2"]))
    for item in news:
        text = item.to_md() if hasattr(item, "to_md") else str(item)
        story.append(Paragraph(text, styles["BodyText"]))
    story.append(Spacer(1, 12))

    # Advisory section
    story.append(Paragraph("KISA 보안 공지", styles["Heading2"]))
    for adv in advisories:
        text = adv.to_md() if hasattr(adv, "to_md") else str(adv)
        story.append(Paragraph(text, styles["BodyText"]))
    story.append(Spacer(1, 12))

    # IOC section
    story.append(Paragraph("ASEC IOC", styles["Heading2"]))
    for category in ("ip", "hash", "url"):
        items = sorted(iocs.get(category, []))
        story.append(Paragraph(f"{category.upper()} ({len(items)})", styles["Heading3"]))
        for entry in items:
            story.append(Paragraph(str(entry), styles["BodyText"]))
        story.append(Spacer(1, 6))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()


# -----------------------------------------------------------------------------
# Mail senders
# -----------------------------------------------------------------------------


def send(msg: EmailMessage) -> None:
    """
    Send *msg* via Gmail SMTP (SSL).

    The function auto‑selects XOAUTH2 vs AppPassword based on available envs.
    """
    user, secret = _get_auth_credentials()

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context) as server:
        if SMTP_XOAUTH2_TOKEN:
            server.docmd("AUTH", f"XOAUTH2 {secret}")
        else:
            server.login(user, secret)  # App‑Password

        server.send_message(msg)
        logger.info("E‑mail successfully sent to %s", ", ".join(MAIL_TO))


def send_digest(
    news: Iterable,
    advisories: Iterable,
    iocs: dict,
    *,
    subject: str | None = None,
) -> None:
    """
    Build a daily digest e‑mail from collected data and send it.

    Parameters
    ----------
    news, advisories:
        Iterables produced by `secbot.fetchers.news.get` / `advisory.get`.
    iocs:
        Dict as returned by `secbot.fetchers.asec.get_iocs`.
    subject:
        Optional custom subject line.
    """
    """
    Build a daily digest e‑mail by sending each section separately.
    """
    # determine today's date
    date_str = _dt.date.today().strftime("%Y-%m-%d")

    # send each section as its own email
    send_security_news(news, subject=subject or f"[관제공화국] 보안정보뉴스 {date_str}")
    # Only send advisory if there are advisories for today
    if advisories:
        send_advisories(advisories, subject=subject or f"[관제공화국] KISA 보안공지 {date_str}")
    send_iocs(iocs, subject=subject or f"[관제공화국] ASEC IOC {date_str}")

def send_security_news(news: Iterable, *, subject: str | None = None) -> None:
    """
    Send only the Security News section as an email.
    """
    today = _dt.date.today()
    msg = EmailMessage()
    msg["From"] = SMTP_USER
    msg["To"] = ", ".join(MAIL_TO)
    msg["Subject"] = subject or f"[관제공화국] 보안뉴스 {today:%Y-%m-%d}"
    # Build news-only body
    lines: List[str] = [
        f"🛡️  보안뉴스 – {today:%Y-%m-%d}",
        "=" * 50,
        "\n[ 보안뉴스 ]"
    ]
    lines.extend(
        item.to_md() if hasattr(item, "to_md") else f"- {item}"
        for item in news
    )
    lines.append("\n— Sent automatically by 관제공화국\n")
    msg.set_content("\n".join(lines))
    send(msg)

def send_advisories(advisories: Iterable, *, subject: str | None = None) -> None:
    """
    Send only the Vulnerability / Advisory section as an email.
    """
    today = _dt.date.today()
    msg = EmailMessage()
    msg["From"] = SMTP_USER
    msg["To"] = ", ".join(MAIL_TO)
    msg["Subject"] = subject or f"[관제공화국] KISA 보안공지 {today:%Y-%m-%d}"
    # Build advisory-only body
    lines: List[str] = [
        f"🛡️  KISA 보안공지 – {today:%Y-%m-%d}",
        "=" * 50,
        "\n[ KISA 보안공지]"
    ]
    lines.extend(
        adv.to_md() if hasattr(adv, "to_md") else f"- {adv}"
        for adv in advisories
    )
    lines.append("\n— Sent automatically by 관제공화국\n")
    msg.set_content("\n".join(lines))
    send(msg)

def send_iocs(iocs: dict, *, subject: str | None = None) -> None:
    """
    Send only the Malicious IOC section as an email.
    """
    today = _dt.date.today()
    msg = EmailMessage()
    msg["From"] = SMTP_USER
    msg["To"] = ", ".join(MAIL_TO)
    msg["Subject"] = subject or f"[관제공화국] ASEC IOC {today:%Y-%m-%d}"
    # Build IOC-only body
    lines: List[str] = [
        f"🛡️  ASEC IOC – {today:%Y-%m-%d}",
        "=" * 50,
        "\n[ ASEC IOC ]",
        "\n수집된 IOC",
    ]
    # 악성 파일, 악성 URL, 악성 IP with counts
    hash_count = sorted(iocs.get("hash_count", []))
    lines.append(f"· 악성 파일 {hash_count[0] if hash_count else '0'}")
    url_count = sorted(iocs.get("url_count", []))
    lines.append(f"· 악성 URL {url_count[0] if url_count else '0'}")
    ip_count = sorted(iocs.get("ip_count", []))
    lines.append(f"· 악성 IP {ip_count[0] if ip_count else '0'}")

    # 네트워크 공격 국가 section
    countries = sorted(iocs.get("network_country", []))
    country_count = sorted(iocs.get("country_count", []))
    lines.append("\n네트워크 공격 국가")
    if countries and country_count:
        # Assume Top1 only
        lines.append(f"Top1 {countries[0]} · {country_count[0]}")
    else:
        lines.append("정보 없음")

    # 네트워크 공격 대상 포트 section
    ports = sorted(iocs.get("network_port", []))
    port_count = sorted(iocs.get("port_count", []))
    lines.append("\n네트워크 공격 대상 포트")
    if ports and port_count:
        lines.append(f"Top1 {ports[0]} · {port_count[0]}")
    else:
        lines.append("정보 없음")

    # --- 여기서부터 세부 IOC 목록 추가 ---
    ips = sorted(iocs.get("ip", []))
    if ips:
        lines.append("\n악성 IP 목록:")
        for ip in ips:
            lines.append(f"    - {ip}")

    hashes = sorted(iocs.get("hash", []))
    if hashes:
        lines.append("\n악성 파일(해시) 목록:")
        for h in hashes:
            lines.append(f"    - {h}")

    urls = sorted(iocs.get("url", []))
    if urls:
        lines.append("\n악성 URL 목록:")
        for u in urls:
            lines.append(f"    - {u}")
    # --- 세부 IOC 목록 끝 ---

    lines.append("\n— Sent automatically by 관제공화국\n")
    msg.set_content("\n".join(lines))
    send(msg)


# -----------------------------------------------------------------------------
# PDF Report sender
# -----------------------------------------------------------------------------

def send_report(news, advisories, iocs, *, subject: str | None = None) -> None:
    """
    Send a combined PDF report as an attachment via Gmail SMTP.
    """
    today = _dt.date.today()
    date_str = today.strftime("%Y-%m-%d")
    msg = EmailMessage()
    msg["From"] = SMTP_USER
    msg["To"] = ", ".join(MAIL_TO)
    msg["Subject"] = subject or f"[SecBot] Daily Security Report {date_str}"
    # Plain-text fallback
    msg.set_content(f"Please find attached the Daily Security Report for {date_str}.")
    # Attach PDF
    pdf_bytes = generate_pdf_report(news, advisories, iocs)
    filename = f"security_report_{date_str}.pdf"
    msg.add_attachment(pdf_bytes, maintype="application", subtype="pdf", filename=filename)
    send(msg)