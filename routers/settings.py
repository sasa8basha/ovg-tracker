"""
routers/settings.py — User settings routes.

Covers: get settings, CPM settings, profile update, password change,
        logout-all, delete account.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, Response, BackgroundTasks
from sqlalchemy.orm import Session

from config import SESSION_COOKIE, SESSION_TTL, USERNAME_RE, PUBLIC_URL
from database import get_db
from models import UserModel, SiteModel, VisitModel, PasswordResetToken, EmailVerificationToken
from schemas import (
    CPMSettingsIn, ProfileUpdateIn, ChangePasswordIn, DeleteAccountIn,
)
from auth import (
    hash_password, verify_password, password_strength,
    is_valid_email, normalize_email, make_token, current_user,
    create_email_verification_token,
)
from email_service import send_email_verification
from utils import stats_cache

router = APIRouter()


@router.get("")
def get_settings(user: UserModel = Depends(current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "email_verified": bool(user.email_verified),
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "cpm_buy": float(user.cpm_buy or 1.0),
        "cpm_sell": float(user.cpm_sell or 1.5),
    }


@router.get("/cpm")
def get_cpm_settings(user: UserModel = Depends(current_user)):
    return {
        "cpm_buy": float(user.cpm_buy or 1.0),
        "cpm_sell": float(user.cpm_sell or 1.5),
    }


@router.post("/cpm")
def update_cpm_settings(payload: CPMSettingsIn,
                        user: UserModel = Depends(current_user),
                        db: Session = Depends(get_db)):
    user.cpm_buy = float(payload.cpm_buy)
    user.cpm_sell = float(payload.cpm_sell)
    db.commit()
    db.refresh(user)
    stats_cache.invalidate(f"stats:user:{user.id}:all")
    return {"ok": True, "cpm_buy": user.cpm_buy, "cpm_sell": user.cpm_sell}


@router.patch("/profile")
def update_profile(payload: ProfileUpdateIn, request: Request,
                   background_tasks: BackgroundTasks,
                   user: UserModel = Depends(current_user),
                   db: Session = Depends(get_db)):
    changed_username = False
    changed_email = False

    new_username = payload.username.strip() if payload.username else ""
    new_email = normalize_email(payload.email) if payload.email else ""

    if new_username and new_username != user.username:
        if not USERNAME_RE.match(new_username):
            raise HTTPException(400, "اسم المستخدم لازم 3-32 حرف (إنجليزي وأرقام و _ . -)")
        if db.query(UserModel).filter(UserModel.username == new_username,
                                      UserModel.id != user.id).first():
            raise HTTPException(400, "اسم المستخدم مستخدم بالفعل")
        user.username = new_username
        changed_username = True

    if new_email and new_email != (user.email or ""):
        if not is_valid_email(new_email):
            raise HTTPException(400, "البريد الإلكتروني غير صالح")
        if db.query(UserModel).filter(UserModel.email == new_email,
                                      UserModel.id != user.id).first():
            raise HTTPException(400, "البريد الإلكتروني مستخدم بالفعل")
        user.email = new_email
        user.email_verified = False
        changed_email = True

    db.commit()
    db.refresh(user)

    if changed_email:
        raw_token = create_email_verification_token(user.id, db)
        if raw_token:
            verify_url = f"{PUBLIC_URL}/verify-email?token={raw_token}"
            background_tasks.add_task(send_email_verification, user.email, user.username, verify_url)

    return {
        "ok": True,
        "username": user.username,
        "email": user.email,
        "email_verified": bool(user.email_verified),
        "changed_username": changed_username,
        "changed_email": changed_email,
    }


@router.post("/change-password")
def change_password(payload: ChangePasswordIn, response: Response,
                    user: UserModel = Depends(current_user),
                    db: Session = Depends(get_db)):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(400, "كلمة المرور الحالية غلط")
    ok, reason = password_strength(payload.new_password)
    if not ok:
        raise HTTPException(400, reason)
    if verify_password(payload.new_password, user.password_hash):
        raise HTTPException(400, "كلمة المرور الجديدة مطابقة للقديمة")

    user.password_hash = hash_password(payload.new_password)
    user.token_version = int(user.token_version or 1) + 1
    db.commit()
    db.refresh(user)

    response.set_cookie(SESSION_COOKIE, make_token(user), httponly=True,
                        samesite="lax", max_age=SESSION_TTL, path="/")
    return {"ok": True, "message": "تم تغيير كلمة المرور. باقي الأجهزة اتسجلت خروج."}


@router.post("/logout-all")
def logout_all(response: Response, user: UserModel = Depends(current_user),
               db: Session = Depends(get_db)):
    user.token_version = int(user.token_version or 1) + 1
    db.commit()
    db.refresh(user)
    response.set_cookie(SESSION_COOKIE, make_token(user), httponly=True,
                        samesite="lax", max_age=SESSION_TTL, path="/")
    return {"ok": True, "message": "تم تسجيل الخروج من باقي الأجهزة"}


@router.delete("/account")
def delete_account(payload: DeleteAccountIn, response: Response,
                   user: UserModel = Depends(current_user),
                   db: Session = Depends(get_db)):
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(400, "كلمة المرور غلط")
    if payload.confirm.strip() != user.username:
        raise HTTPException(400, "لازم تكتب اسم المستخدم بالظبط للتأكيد")

    try:
        site_ids = [s.id for s in db.query(SiteModel.id).filter(SiteModel.user_id == user.id).all()]
        if site_ids:
            db.query(VisitModel).filter(VisitModel.site_id.in_(site_ids)).delete(synchronize_session=False)
        db.query(SiteModel).filter(SiteModel.user_id == user.id).delete(synchronize_session=False)
        db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).delete(synchronize_session=False)
        db.query(EmailVerificationToken).filter(EmailVerificationToken.user_id == user.id).delete(synchronize_session=False)
        db.delete(user)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Delete failed: {e}")

    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}
