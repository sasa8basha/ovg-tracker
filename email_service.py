import asyncio
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
import httpx
from config import (
    EMAIL_PROVIDER, EMAIL_FROM, EMAIL_FROM_NAME, PUBLIC_URL,
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_USE_TLS,
    RESEND_API_KEY,
)

def _send_smtp_sync(to: str, subject: str, html: str, text: str):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS: return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = formataddr((EMAIL_FROM_NAME, EMAIL_FROM))
        msg["To"] = to
        msg.attach(MIMEText(text, "plain", "utf-8"))
        msg.attach(MIMEText(html, "html", "utf-8"))
        if SMTP_USE_TLS:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
                s.starttls(); s.login(SMTP_USER, SMTP_PASS); s.sendmail(EMAIL_FROM, [to], msg.as_string())
        else:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15) as s:
                s.login(SMTP_USER, SMTP_PASS); s.sendmail(EMAIL_FROM, [to], msg.as_string())
    except Exception as e: print(f"⚠️ SMTP send failed: {e}")

async def _send_resend(to: str, subject: str, html: str, text: str):
    if not RESEND_API_KEY: return
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
                json={"from": f"{EMAIL_FROM_NAME} <{EMAIL_FROM}>", "to": [to], "subject": subject, "html": html, "text": text},
            )
            if r.status_code >= 300: print(f"⚠️ Resend error: {r.status_code} {r.text[:200]}")
    except Exception as e: print(f"⚠️ Resend exception: {e}")

async def send_email(to: str, subject: str, html: str, text: str = ""):
    if not to: return
    if EMAIL_PROVIDER == "console":
        print("\n" + "=" * 70)
        print(f"📧 EMAIL [console]\nTo: {to}\nFrom: {EMAIL_FROM_NAME} <{EMAIL_FROM}>\nSubject: {subject}\n" + "-" * 70)
        print(text or "(html-only)")
        print("=" * 70 + "\n")
        return
    if EMAIL_PROVIDER == "smtp":
        await asyncio.to_thread(_send_smtp_sync, to, subject, html, text or html)
    elif EMAIL_PROVIDER == "resend":
        await _send_resend(to, subject, html, text or html)

def _wrap_html(title: str, body_html: str) -> str:
    return f"""<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>{title}</title></head>
<body style="margin:0;padding:0;background:#0F172A;font-family:Arial,sans-serif;color:#F1F5F9">
<table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#0F172A"><tr><td align="center" style="padding:40px 16px">
<table width="600" cellspacing="0" cellpadding="0" border="0" style="max-width:600px;width:100%;background:#1E293B;border-radius:16px;overflow:hidden">
<tr><td style="padding:28px 40px;border-bottom:1px solid #334155"><div style="font-size:22px;font-weight:800;">🛡️ OVG Tracker</div></td></tr>
<tr><td style="padding:36px 40px">{body_html}</td></tr>
<tr><td style="padding:24px 40px;background:#0F172A;color:#64748B;font-size:12px;text-align:center">© OVG Tracker</td></tr>
</table></td></tr></table></body></html>"""

def build_password_reset_email(username: str, otp: str) -> tuple[str, str, str]:
    subject = "🔐 كود إعادة تعيين كلمة المرور — OVG Tracker"
    body_html = f"""
    <h1 style="margin:0 0 12px;font-size:22px;color:#F1F5F9">إعادة تعيين كلمة المرور</h1>
    <p style="margin:0 0 8px;font-size:15px;color:#CBD5E1;">أهلاً <b style="color:#F1F5F9">{username}</b>،</p>
    <p style="margin:0 0 20px;font-size:15px;color:#CBD5E1;line-height:1.7">
    وصلنا طلب لإعادة تعيين كلمة المرور. استخدم الكود التالي في الصفحة لإكمال العملية:
    </p>
    <div style="text-align:center;background:#0F172A;border:1px dashed #6366F1;border-radius:12px;padding:20px;margin:20px 0;">
        <span style="font-size:36px;font-weight:800;letter-spacing:8px;color:#818CF8;font-family:monospace;">{otp}</span>
    </div>
    <p style="margin:16px 0 0;font-size:13px;color:#94A3B8;line-height:1.7">
    ⏱️ الكود صالح لمدة <b>ساعة واحدة</b> فقط.<br>
    🔒 لو مش إنت اللي طلبت ده، تجاهل الإيميل.
    </p>
    """
    text = f"OVG Tracker\n\nأهلاً {username}،\n\nكود إعادة تعيين كلمة المرور الخاص بك هو:\n\n{otp}\n\nالكود صالح لمدة ساعة واحدة."
    return subject, _wrap_html(subject, body_html), text

def build_email_verification_email(username: str, verify_url: str) -> tuple[str, str, str]:
    subject = "✅ فعّل بريدك الإلكتروني — OVG Tracker"
    body_html = f"""
    <h1 style="margin:0 0 12px;font-size:22px;color:#F1F5F9">فعّل بريدك الإلكتروني</h1>
    <p style="margin:0 0 8px;font-size:15px;color:#CBD5E1;">أهلاً <b style="color:#F1F5F9">{username}</b>،</p>
    <p style="margin:0 0 16px;font-size:15px;color:#CBD5E1;line-height:1.7">شكرًا لتسجيلك! فعّل بريدك دلوقتي لتأمين حسابك.</p>
    <div style="text-align:center;margin:24px 0;">
        <a href="{verify_url}" style="background:#10B981;color:#fff;padding:14px 32px;text-decoration:none;border-radius:12px;font-weight:700;">تفعيل البريد</a>
    </div>
    """
    text = f"OVG Tracker\n\nافتح الرابط لتفعيل بريدك:\n{verify_url}"
    return subject, _wrap_html(subject, body_html), text

def build_welcome_email(username: str) -> tuple[str, str, str]:
    subject = "🎉 أهلاً بيك في OVG Tracker"
    body_html = f"""
    <h1 style="margin:0 0 12px;font-size:22px;color:#F1F5F9">أهلاً بيك في OVG Tracker</h1>
    <p style="margin:0 0 8px;font-size:15px;color:#CBD5E1;">أهلاً <b style="color:#F1F5F9">{username}</b>،</p>
    <p style="margin:0 0 16px;font-size:15px;color:#CBD5E1;line-height:1.7">حسابك جاهز. أضف أول موقع ليك وابدأ تتبع الترافيك.</p>
    """
    text = f"OVG Tracker\n\nحسابك جاهز."
    return subject, _wrap_html(subject, body_html), text

async def send_password_reset_email(to: str, username: str, otp: str):
    subject, html, text = build_password_reset_email(username, otp)
    await send_email(to, subject, html, text)

async def send_email_verification(to: str, username: str, verify_url: str):
    subject, html, text = build_email_verification_email(username, verify_url)
    await send_email(to, subject, html, text)

async def send_welcome_email(to: str, username: str):
    subject, html, text = build_welcome_email(username)
    await send_email(to, subject, html, text)
