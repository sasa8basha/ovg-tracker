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


# =========================================================
# PASSWORD HASHING
# =========================================================
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
    """
    Returns (ok, reason).
    Requires: 8+ chars, at least 2 of: lower / upper / digit / special.
    """
    if not pw or len(pw) < 8:
        return False, "كلمة المرور لازم 8 حروف على الأقل"
    if len(pw) > 128:
        return False, "كلمة المرور طويلة جداً (حد أقصى 128 حرف)"
    score = 0
    if any(c.islower() for c in pw): score += 1
    if any(c.isupper() for c in pw): score += 1
    if any(c.isdigit() for c in pw): score += 1
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/~`" for c in pw): score += 1
    if score < 2:
        return False, "كلمة المرور ضعيفة — لازم تحتوي على حرفين مختلفين على الأقل (كبير، صغير، رقم، رمز)"
    return True, ""


def is_valid_email(email: str) -> bool:
    if not email or len(email) > 254:
        return False
    return bool(EMAIL_RE.match(email.strip()))


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


# =========================================================
# SESSION TOKENS (with version)
# =========================================================
def make_token(user: UserModel) -> str:
    """
    Format: {user_id}.{exp}.{version}.{sig}
    """
    exp = int(time.time()) + SESSION_TTL
    version = int(user.token_version or 1)
    payload = f"{user.id}.{exp}.{version}"
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_token(token: str, db: Session = None):
    """
    Returns user_id (int) if valid, else None.
    - Backward compatible with old 3-part tokens (treat version as 1).
    - If db provided, checks token_version matches user's current version.
    """
    if not token:
        return None
    try:
        parts = token.split(".")
        if len(parts) == 3:
            # Old format: user_id.exp.sig
            user_id_str, exp_str, sig = parts
            version_str = None
            payload = f"{user_id_str}.{exp_str}"
        elif len(parts) == 4:
            # New format: user_id.exp.version.sig
            user_id_str, exp_str, version_str, sig = parts
            payload = f"{user_id_str}.{exp_str}.{version_str}"
        else:
            return None

        expected = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        if int(exp_str) < time.time():
            return None

        user_id = int(user_id_str)

        if db is not None:
            user = db.query(UserModel).get(user_id)
            if not user:
                return None
            expected_version = int(user.token_version or 1)
            actual_version = int(version_str) if version_str else 1
            if actual_version != expected_version:
                return None

        return user_id
    except Exception:
        return None


def _optional_user(request: Request, db: Session):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        uid = verify_token(token, db=db)
        if uid:
            u = db.query(UserModel).get(uid)
            if u:
                return u
    key = request.query_params.get("key") or request.headers.get("x-api-key")
    if DASHBOARD_KEY and key == DASHBOARD_KEY:
        return db.query(UserModel).first()
    return None


def current_user(request: Request, db: Session = Depends(get_db)) -> UserModel:
    user = _optional_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user


# =========================================================
# PASSWORD RESET TOKENS
# =========================================================
def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


def create_password_reset_token(user_id: int, ip: str, db: Session):
    """
    Generates a new reset token, invalidates old unused ones for same user.
    Returns the raw token (never stored) or None on error.
    """
    try:
        now = datetime.utcnow()
        # Invalidate old unused tokens
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user_id,
            PasswordResetToken.used_at.is_(None),
        ).delete(synchronize_session=False)

        raw = secrets.token_urlsafe(32)
        row = PasswordResetToken(
            user_id=user_id,
            token_hash=_hash_token(raw),
            expires_at=now + timedelta(seconds=RESET_TOKEN_TTL),
            ip=str(ip or "")[:45],
        )
        db.add(row)
        db.commit()
        return raw
    except Exception as e:
        print(f"create_password_reset_token error: {e}")
        try:
            db.rollback()
        except Exception:
            pass
        return None


def consume_password_reset_token(raw_token: str, db: Session):
    """Returns UserModel if token valid & unused, else None. Marks token as used."""
    if not raw_token:
        return None
    try:
        th = _hash_token(raw_token)
        now = datetime.utcnow()
        tok = db.query(PasswordResetToken).filter(
            PasswordResetToken.token_hash == th,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        ).first()
        if not tok:
            return None
        user = db.query(UserModel).get(tok.user_id)
        if not user:
            return None
        tok.used_at = now
        db.commit()
        return user
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return None


# =========================================================
# EMAIL VERIFICATION TOKENS
# =========================================================
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
        try:
            db.rollback()
        except Exception:
            pass
        return None


def consume_email_verification_token(raw_token: str, db: Session):
    if not raw_token:
        return None
    try:
        th = _hash_token(raw_token)
        now = datetime.utcnow()
        tok = db.query(EmailVerificationToken).filter(
            EmailVerificationToken.token_hash == th,
            EmailVerificationToken.used_at.is_(None),
            EmailVerificationToken.expires_at > now,
        ).first()
        if not tok:
            return None
        user = db.query(UserModel).get(tok.user_id)
        if not user:
            return None
        tok.used_at = now
        user.email_verified = True
        db.commit()
        db.refresh(user)
        return user
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return None


# =========================================================
# BOOTSTRAP ADMIN
# =========================================================
def bootstrap_admin():
    if not ADMIN_USER or not ADMIN_PASS:
        return
    db = SessionLocal()
    try:
        if db.query(UserModel).filter(UserModel.username == ADMIN_USER).first():
            return
        db.add(UserModel(username=ADMIN_USER, password_hash=hash_password(ADMIN_PASS)))
        db.commit()
        print(f"✅ Bootstrapped admin user: {ADMIN_USER}")
    finally:
        db.close()
