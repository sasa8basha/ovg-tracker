"""
helpers.py — Shared helper functions.
"""
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
from fastapi import HTTPException
from sqlalchemy.orm import Session

from models import UserModel, VisitModel, CampaignModel

def csv_safe(val):
    if val is None: return ""
    s = str(val)
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r'): return "'" + s
    return s

def _country_key(country_code, country_name):
    code = (country_code or "").strip().upper()
    if code and code not in ("LO", "XX"): return code
    return (country_name or "Unknown").strip() or "Unknown"

def _parse_date(s):
    if not s: return None
    try: return datetime.strptime(str(s).strip(), "%Y-%m-%d")
    except (ValueError, TypeError): return None

def _apply_date_filter(q, from_date, to_date):
    fd = _parse_date(from_date)
    td = _parse_date(to_date)
    if fd: q = q.filter(VisitModel.timestamp >= fd)
    if td: q = q.filter(VisitModel.timestamp < (td + timedelta(days=1)))
    return q

def _safe_filename(base, *parts):
    s = "_".join([base] + [str(p) for p in parts if p])
    s = re.sub(r"[^a-zA-Z0-9_.-]", "_", s)[:100]
    return (s or "export") + ".csv"

def _resolve_user_campaign(campaign_key_or_id, user: UserModel, db: Session) -> CampaignModel:
    if not campaign_key_or_id: raise HTTPException(400, "campaign مطلوب")
    q = db.query(CampaignModel).filter(CampaignModel.user_id == user.id)
    if isinstance(campaign_key_or_id, int): q = q.filter(CampaignModel.id == campaign_key_or_id)
    else:
        key = str(campaign_key_or_id).strip()
        if key.isdigit(): q = q.filter(CampaignModel.id == int(key))
        else: q = q.filter(CampaignModel.campaign_key == key)
    c = q.first()
    if not c: raise HTTPException(404, "الحملة مش موجودة أو مش بتاعتك")
    return c

def extract_zone_id_from_url(url: str) -> str:
    if not url or url == "unknown": return ""
    try: parsed = urlparse(url)
    except Exception: return ""
    try:
        for k, v in parse_qs(parsed.query or "").items():
            kl = (k or "").lower().strip()
            if kl in ("zoneid", "zone_id", "zone", "z"):
                if v and v[0]:
                    val = str(v[0]).strip()
                    if val and len(val) <= 100: return val
    except Exception: pass
    try:
        parts = [p for p in (parsed.path or "").split("/") if p]
        for i, p in enumerate(parts):
            pl = (p or "").lower().strip()
            if pl in ("zone", "z", "zoneid") and i + 1 < len(parts):
                nxt = parts[i + 1]
                if nxt and len(nxt) <= 100: return nxt
    except Exception: pass
    try:
        parts = [p for p in (parsed.path or "").split("/") if p]
        if parts:
            first = parts[0]
            if first.isdigit() and 4 <= len(first) <= 10: return first
    except Exception: pass
    return ""

def extract_zone_id(url: str) -> str:
    result = extract_zone_id_from_url(url)
    return result if result else "unknown"
