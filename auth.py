import time
import hmac
import hashlib
import secrets
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from config import SECRET, SESSION_TTL, SESSION_COOKIE, DASHBOARD_KEY, ADMIN_USER, ADMIN_PASS
from database import SessionLocal, get_db
from models import UserModel

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

def make_token(user_id: int) -> str:
    exp = int(time.time()) + SESSION_TTL
    payload = f"{user_id}.{exp}"
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"

def verify_token(token: str):
    try:
        user_id, exp, sig = token.rsplit(".", 2)
        payload = f"{user_id}.{exp}"
        expected = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        if int(exp) < time.time():
            return None
        return int(user_id)
    except Exception:
        return None

def _optional_user(request: Request, db: Session):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        uid = verify_token(token)
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
