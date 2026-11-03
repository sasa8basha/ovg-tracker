"""
email_service.py — Phase 5

Pluggable email sender:
  - "console": prints to logs (dev)
  - "smtp":    standard SMTP
  - "resend":  https://resend.com API
"""
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

# =========================================================
# LOW-LEVEL SENDERS
# =========================================================
def _send_smtp_sync(to: str, subject: str, html: str, text: str):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        print("⚠️ SMTP not configured — skipping send")
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = formataddr((EMAIL_FROM_NAME, EMAIL_FROM))
        msg["To"] = to
        msg.attach(MIMEText(text, "plain", "utf-8"))
        msg.attach(MIMEText(html, "html", "utf-8"))

        if SMTP_USE_TLS:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
                s.starttls()
                s.login(SMTP_USER, SMTP_PASS)
                s.sendmail(EMAIL_FROM, [to], msg.as_string())
        else:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15) as s:
                s.login(SMTP_USER, SMTP_PASS)
                s.sendmail(EMAIL_FROM, [to], msg.as_string())
        print(f"✅ SMTP sent to {to}")
    except Exception as e:
        print(f"⚠️ SMTP send failed: {e}")


async def _send_resend(to: str, subject: str, html: str, text: str):
    if not RESEND_API_KEY:
        print("⚠️ RESEND_API_KEY not set — skipping send")
        return
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": f"{EMAIL_FROM_NAME} <{EMAIL_FROM}>",
                    "to": [to],
                    "subject": subject,
                    "html": html,
                    "text": text,
                },
            )
            if r.status_code >= 300:
                print(f"⚠️ Resend error: {r.status_code} {r.text[:200]}")
            else:
                print(f"✅ Resend sent to {to}")
    except Exception as e:
        print(f"⚠️ Resend exception: {e}")


async def send_email(to: str, subject: str, html: str, text: str = ""):
    if not to:
        return
    if EMAIL_PROVIDER == "console":
        print("\n" + "=" * 70)
        print(f"📧 EMAIL [console]")
        print(f"To:      {to}")
        print(f"From:    {EMAIL_FROM_NAME} <{EMAIL_FROM}>")
        print(f"Subject: {subject}")
        print("-" * 70)
        print(text or "(html-only — see file logs)")
        print("=" * 70 + "\n")
        return
    if EMAIL_PROVIDER == "smtp":
        await asyncio.to_thread(_send_smtp_sync, to, subject, html, text or html)
        return
    if EMAIL_PROVIDER == "resend":
        await _send_resend(to, subject, html, text or html)
        return
    print(f"⚠️ Unknown EMAIL_PROVIDER: {EMAIL_PROVIDER}")


# =========================================================
# HTML TEMPLATE
# =========================================================
def _wrap_html(title: str, body_html: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title></head>
<body style="margin:0;padding:0;background:#0F172A;font-family:Arial,Helvetica,sans-serif;color:#F1F5F9">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#0F172A">
<tr><td align="center" style="padding:40px 16px">
<table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width:600px;width:100%;background:#1E293B;border-radius:16px;overflow:hidden;box-shadow:0 8px 32px rgba(0,0,0,.4)">
<tr><td style="padding:28px 40px;border-bottom:1px solid #334155;background:#1E293B">
<div style="font-size:22px;font-weight:800;color:#F1F5F9">🛡️ OVG Tracker</div>
</td></tr>
<tr><td style="padding:36px 40px">{body_html}</td></tr>
<tr><td style="padding:24px 40px;background:#0F172A;border-top:1px solid #334155;color:#64748B;font-size:12px;line-height:1.6">
لو مش إنت اللي طلبت ده، تقدر تتجاهل الإيميل بأمان.<br>
© OVG Tracker · <a href="{PUBLIC_URL}" style="color:#818CF8;text-decoration:none">{PUBLIC_URL}</a>
</td></tr>
</table>
</td></tr>
</table>
</body></html>"""


def _btn(url: str, label: str, color: str = "#6366F1") -> str:
    return f"""<table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:24px 0">
<tr><td align="center" style="border-radius:12px;background:{color}">
<a href="{url}" target="_blank" style="display:inline-block;padding:14px 32px;font-size:15px;font-weight:700;color:#fff;text-decoration:none;border-radius:12px">{label}</a>
</td></tr></table>"""


# =========================================================
# EMAIL BUILDERS
# =========================================================
def build_password_reset_email(username: str, reset_url: str) -> tuple[str, str, str]:
    subject = "🔐 إعادة تعيين كلمة المرور — OVG Tracker"
    body_html = f"""
<h1 style="margin:0 0 12px;font-size:22px;color:#F1F5F9">إعادة تعيين كلمة المرور</h1>
<p style="margin:0 0 8px;font-size:15px;color:#CBD5E1;line-height:1.7">أهلاً <b style="color:#F1F5F9">{username}</b>،</p>
<p style="margin:0 0 8px;font-size:15px;color:#CBD5E1;line-height:1.7">
وصلنا طلب لإعادة تعيين كلمة المرور على حسابك في OVG Tracker. اضغط على الزر أدناه لإنشاء كلمة مرور جديدة.
</p>
{_btn(reset_url, "إعادة تعيين كلمة المرور", "#6366F1")}
<p style="margin:16px 0 0;font-size:13px;color:#94A3B8;line-height:1.7">
⏱️ الرابط صالح لمدة <b>ساعة واحدة</b> فقط.<br>
🔒 لو مش إنت اللي طلبت ده، تجاهل الإيميل — كلمة المرور مش هتتغير.
</p>
"""
    # تم إضافة الأقواس < > حوالين الرابط عشان نمنع تقطيعه في النص المجرد
    text = f"""OVG Tracker — إعادة تعيين كلمة المرور

أهلاً {username}،

اضغط على الرابط التالي لإنشاء كلمة مرور جديدة:
<{reset_url}>

الرابط صالح لمدة ساعة واحدة فقط.

لو مش إنت اللي طلبت ده، تجاهل الإيميل.
"""
    return subject, _wrap_html(subject, body_html), text


def build_email_verification_email(username: str, verify_url: str) -> tuple[str, str, str]:
    subject = "✅ فعّل بريدك الإلكتروني — OVG Tracker"
    body_html = f"""
<h1 style="margin:0 0 12px;font-size:22px;color:#F1F5F9">فعّل بريدك الإلكتروني</h1>
<p style="margin:0 0 8px;font-size:15px;color:#CBD5E1;line-height:1.7">أهلاً <b style="color:#F1F5F9">{username}</b>،</p>
<p style="margin:0 0 8px;font-size:15px;color:#CBD5E1;line-height:1.7">
شكرًا لتسجيلك في OVG Tracker! فعّل بريدك دلوقتي عشان نضمن إنك تقدر تستعيد حسابك في أي وقت.
</p>
{_btn(verify_url, "تفعيل البريد الإلكتروني", "#10B981")}
<p style="margin:16px 0 0;font-size:13px;color:#94A3B8;line-height:1.7">
⏱️ الرابط صالح لمدة 24 ساعة.<br>
لو مش إنت اللي سجلت، تجاهل الإيميل.
</p>
"""
    text = f"""OVG Tracker — تفعيل البريد الإلكتروني

أهلاً {username}،

افتح الرابط التالي لتفعيل بريدك:
<{verify_url}>

الرابط صالح لمدة 24 ساعة.
"""
    return subject, _wrap_html(subject, body_html), text


def build_welcome_email(username: str) -> tuple[str, str, str]:
    subject = "🎉 أهلاً بيك في OVG Tracker"
    body_html = f"""
<h1 style="margin:0 0 12px;font-size:22px;color:#F1F5F9">أهلاً بيك في OVG Tracker</h1>
<p style="margin:0 0 8px;font-size:15px;color:#CBD5E1;line-height:1.7">أهلاً <b style="color:#F1F5F9">{username}</b>،</p>
<p style="margin:0 0 16px;font-size:15px;color:#CBD5E1;line-height:1.7">
حسابك جاهز. خطوتك التالية: أضف أول موقع ليك وابدأ تتبع الترافيك في دقيقة واحدة.
</p>
{_btn(PUBLIC_URL + "/dashboard", "اذهب للداشبورد")}
<ul style="margin:16px 0 0;padding:0 20px;color:#CBD5E1;font-size:14px;line-height:1.9">
  <li>أضف موقعك من صفحة "المواقع"</li>
  <li>انسخ كود التتبع وحطه في موقعك</li>
  <li>شاهد التحليل لحظة بلحظة</li>
</ul>
"""
    text = f"""OVG Tracker — أهلاً بيك!

حسابك جاهز. ابدأ من:
{PUBLIC_URL}/dashboard
"""
    return subject, _wrap_html(subject, body_html), text


# =========================================================
# HIGH-LEVEL SENDERS
# =========================================================
async def send_password_reset_email(to: str, username: str, reset_url: str):
    subject, html, text = build_password_reset_email(username, reset_url)
    await send_email(to, subject, html, text)


async def send_email_verification(to: str, username: str, verify_url: str):
    subject, html, text = build_email_verification_email(username, verify_url)
    await send_email(to, subject, html, text)


async def send_welcome_email(to: str, username: str):
    subject, html, text = build_welcome_email(username)
    await send_email(to, subject, html, text)
