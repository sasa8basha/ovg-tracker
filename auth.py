import time
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from config import (
    SECRET, SESSION_TTL, SESSION_COOKIE, DASHBOARD_KEY,
    ADMIN_USER, ADMIN_PASS, RESET_TOKEN_TTL, VERIFY_TOKEN_TTL,
    EMAIL_RE,
)
from database import SessionLocal, get_db
from models import UserModel, PasswordResetToken, EmailVerificationToken

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
    return f"{salt}${h}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$", 1)
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
        return hmac.compare_digest(calc, h)
    except Exception:
        return False

def password_strength(pw: str) -> tuple[bool, str]:
    if not pw or len(pw) < 8:
        return False, "كلمة المرور لازم 8 حروف على الأقل"
    if len(pw) > 128:
        return False, "كلمة المرور طويلة جداً (حد أقصى 128 حرف)"
    score = 0
    if any(c.islower() for c in pw): score += 1
    if any(c.isupper() for c in pw): score += 1
    if any(c.isdigit() for c in pw): score += 1
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/~`" for c in pw): score += 1
    if score < 3:  # L-20: require 3 character classes
        return False, "كلمة المرور ضعيفة — لازم تحتوي على حرفين مختلفين على الأقل (كبير، صغير، رقم، رمز)"
    return True, ""

def is_valid_email(email: str) -> bool:
    if not email or len(email) > 254: return False
    return bool(EMAIL_RE.match(email.strip()))

def normalize_email(email: str) -> str:
    return (email or "").strip().lower()

def make_token(user: UserModel) -> str:
    exp = int(time.time()) + SESSION_TTL
    version = int(user.token_version or 1)
    payload = f"{user.id}.{exp}.{version}"
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"

def verify_token(token: str, db: Session = None):
    # H-26: full per-session jti table is a future enhancement; token_version covers global revoke
    if not token: return None
    try:
        parts = token.split(".")
        if len(parts) == 3:
            user_id_str, exp_str, sig = parts
            version_str = None
            payload = f"{user_id_str}.{exp_str}"
        elif len(parts) == 4:
            user_id_str, exp_str, version_str, sig = parts
            payload = f"{user_id_str}.{exp_str}.{version_str}"
        else:
            return None
        expected = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig): return None
        if int(exp_str) < time.time(): return None
        user_id = int(user_id_str)
        if db is not None:
            user = db.query(UserModel).filter(UserModel.id == user_id).first()  # M-55
            if not user: return None
            expected_version = int(user.token_version or 1)
            actual_version = int(version_str) if version_str else 1
            if actual_version != expected_version: return None
        return user_id
    except Exception:
        return None

def _optional_user(request: Request, db: Session):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        uid = verify_token(token, db=db)
        if uid:
            u = db.query(UserModel).filter(UserModel.id == uid).first()  # M-55
            if u: return u
    key = request.query_params.get("key") or request.headers.get("x-api-key")
    if DASHBOARD_KEY and key == DASHBOARD_KEY:
        return db.query(UserModel).first()
    return None

def current_user(request: Request, db: Session = Depends(get_db)) -> UserModel:
    user = _optional_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user

def _hash_token(raw_token: str) -> str:
    """HMAC-SHA256 with SECRET as key to prevent rainbow-table attacks on leaked token hashes."""
    return hmac.new(SECRET.encode(), raw_token.encode(), hashlib.sha256).hexdigest()

# =========================================================
# OTP (One-Time Password) Logic
# =========================================================
def create_password_reset_otp(user_id: int, ip: str, db: Session):
    try:
        now = datetime.utcnow()
        # مسح أي أكواد قديمة
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user_id,
            PasswordResetToken.used_at.is_(None),
        ).delete(synchronize_session=False)

        # توليد كود من 6 أرقام
        otp = f"{secrets.randbelow(1000000):06d}"
        
        row = PasswordResetToken(
            user_id=user_id,
            token_hash=_hash_token(otp), # بنحفظ الهاش بتاع الكود للأمان
            expires_at=now + timedelta(seconds=RESET_TOKEN_TTL),
            ip=str(ip or "")[:45],
        )
        db.add(row)
        db.commit()
        return otp
    except Exception as e:
        print(f"create_password_reset_otp error: {e}")
        try: db.rollback()
        except: pass
        return None

def consume_password_reset_otp(user_id: int, otp: str, db: Session):
    if not otp: return False
    try:
        th = _hash_token(otp.strip())
        now = datetime.utcnow()
        tok = db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user_id,
            PasswordResetToken.token_hash == th,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        ).first()
        
        if not tok:
            return False
            
        tok.used_at = now
        db.commit()
        return True
    except Exception:
        try: db.rollback()
        except: pass
        return False

# توثيق الإيميل هيفضل باللينك عادي لأنه بيحصل بعد التسجيل مباشرة
def create_email_verification_token(user_id: int, db: Session):
    try:
        now = datetime.utcnow()
        db.query(EmailVerificationToken).filter(
            EmailVerificationToken.user_id == user_id,
            EmailVerificationToken.used_at.is_(None),
        ).delete(synchronize_session=False)

        raw = secrets.token_urlsafe(32)
        row = EmailVerificationToken(
            user_id=user_id,
            token_hash=_hash_token(raw),
            expires_at=now + timedelta(seconds=VERIFY_TOKEN_TTL),
        )
        db.add(row)
        db.commit()
        return raw
    except Exception as e:
        print(f"create_email_verification_token error: {e}")
        return None

def consume_email_verification_token(raw_token: str, db: Session):
    if not raw_token: return None
    try:
        th = _hash_token(raw_token)
        now = datetime.utcnow()
        tok = db.query(EmailVerificationToken).filter(
            EmailVerificationToken.token_hash == th,
            EmailVerificationToken.used_at.is_(None),
            EmailVerificationToken.expires_at > now,
        ).first()
        if not tok: return None
        user = db.query(UserModel).get(tok.user_id)
        if not user: return None
        tok.used_at = now
        user.email_verified = True
        db.commit()
        db.refresh(user)
        return user
    except Exception:
        try: db.rollback()
        except: pass
        return None

def bootstrap_admin():
    if not ADMIN_USER or not ADMIN_PASS: return
    db = SessionLocal()
    try:
        if db.query(UserModel).filter(UserModel.username == ADMIN_USER).first(): return
        db.add(UserModel(username=ADMIN_USER, password_hash=hash_password(ADMIN_PASS)))
        db.commit()
        print(f"✅ Bootstrapped admin user: {ADMIN_USER}")
    finally:
        db.close()
