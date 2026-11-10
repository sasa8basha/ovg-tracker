"""
routers/auth.py — Authentication routes.

Covers: signup, login, logout, me, forgot-password, reset-password, resend-verification.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, Response, BackgroundTasks
from sqlalchemy.orm import Session

from config import SESSION_COOKIE, SESSION_TTL, USERNAME_RE, PUBLIC_URL
from database import get_db
from models import UserModel
from schemas import (
    AuthIn, ForgotPasswordIn, ResetPasswordIn,
)
from utils import (
    get_client_ip, signup_limiter, login_limiter,
    forgot_password_limiter, reset_password_limiter,
    verify_resend_limiter,
)
from auth import (
    hash_password, verify_password, password_strength,
    is_valid_email, normalize_email, make_token,
    _optional_user, current_user,
    create_password_reset_otp, consume_password_reset_otp,
    create_email_verification_token,
)
from email_service import (
    send_password_reset_email, send_email_verification, send_welcome_email,
)

router = APIRouter()


@router.post("/signup")
def signup(payload: AuthIn, request: Request, response: Response,
           background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    signup_limiter.check(client_ip)

    username = payload.username.strip()
    password = payload.password
    email = normalize_email(payload.email)

    if not USERNAME_RE.match(username):
        raise HTTPException(400, "اسم المستخدم لازم 3-32 حرف (إنجليزي وأرقام و _ . -)")
    ok, reason = password_strength(password)
    if not ok:
        raise HTTPException(400, reason)
    if not is_valid_email(email):
        raise HTTPException(400, "البريد الإلكتروني غير صالح")
    if db.query(UserModel).filter(UserModel.username == username).first():
        raise HTTPException(400, "اسم المستخدم مستخدم بالفعل")
    if db.query(UserModel).filter(UserModel.email == email).first():
        raise HTTPException(400, "البريد الإلكتروني مستخدم بالفعل")

    u = UserModel(
        username=username,
        password_hash=hash_password(password),
        email=email,
        email_verified=False,
        token_version=1,
    )
    db.add(u)
    db.commit()
    db.refresh(u)

    response.set_cookie(SESSION_COOKIE, make_token(u), httponly=True,
                        samesite="lax", max_age=SESSION_TTL, path="/")

    raw_token = create_email_verification_token(u.id, db)
    if raw_token:
        verify_url = f"{PUBLIC_URL}/verify-email?token={raw_token}"
        background_tasks.add_task(send_email_verification, u.email, u.username, verify_url)
    background_tasks.add_task(send_welcome_email, u.email, u.username)
    return {"ok": True, "username": u.username, "email": u.email}


@router.post("/login")
def login(payload: AuthIn, request: Request, response: Response,
          db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    login_limiter.check(client_ip)

    identifier = payload.username.strip()
    u = None
    if identifier:
        u = db.query(UserModel).filter(UserModel.username == identifier).first()
        if not u and "@" in identifier:
            u = db.query(UserModel).filter(UserModel.email == normalize_email(identifier)).first()

    if not u or not verify_password(payload.password, u.password_hash):
        raise HTTPException(401, "بيانات الدخول غلط")

    response.set_cookie(SESSION_COOKIE, make_token(u), httponly=True,
                        samesite="lax", max_age=SESSION_TTL, path="/")
    return {"ok": True, "username": u.username}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
def me(user: UserModel = Depends(current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "email_verified": bool(user.email_verified),
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


@router.post("/forgot-password")
def forgot_password(payload: ForgotPasswordIn, request: Request,
                    background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    forgot_password_limiter.check(client_ip)

    email = normalize_email(payload.email)
    msg = "لو البريد موجود عندنا، هيوصلك كود مكون من 6 أرقام في دقايق."
    if not is_valid_email(email):
        return {"ok": True, "message": msg}

    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user:
        return {"ok": True, "message": msg}

    otp = create_password_reset_otp(user.id, client_ip, db)
    if otp:
        background_tasks.add_task(send_password_reset_email, user.email, user.username, otp)
    return {"ok": True, "message": msg}


@router.post("/reset-password")
def reset_password(payload: ResetPasswordIn, request: Request,
                   response: Response, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    reset_password_limiter.check(client_ip)

    ok, reason = password_strength(payload.new_password)
    if not ok:
        raise HTTPException(400, reason)

    email = normalize_email(payload.email)
    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user:
        raise HTTPException(400, "الكود غير صالح أو الإيميل غير مسجل")
    if not consume_password_reset_otp(user.id, payload.otp, db):
        raise HTTPException(400, "الكود غير صحيح أو منتهي الصلاحية. اطلب كود جديد.")

    user.password_hash = hash_password(payload.new_password)
    user.token_version = int(user.token_version or 1) + 1
    db.commit()
    db.refresh(user)

    response.set_cookie(SESSION_COOKIE, make_token(user), httponly=True,
                        samesite="lax", max_age=SESSION_TTL, path="/")
    return {"ok": True, "message": "تم إعادة تعيين كلمة المرور. باقي الأجهزة اتسجلت خروج."}


@router.post("/resend-verification")
def resend_verification(request: Request, background_tasks: BackgroundTasks,
                        user: UserModel = Depends(current_user),
                        db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    verify_resend_limiter.check(client_ip)

    if not user.email:
        raise HTTPException(400, "مفيش بريد إلكتروني مرتبط بالحساب")
    if user.email_verified:
        return {"ok": True, "message": "البريد مفعّل بالفعل"}

    raw_token = create_email_verification_token(user.id, db)
    if raw_token:
        verify_url = f"{PUBLIC_URL}/verify-email?token={raw_token}"
        background_tasks.add_task(send_email_verification, user.email, user.username, verify_url)
    return {"ok": True, "message": "تم إرسال رابط التفعيل تاني"}
