from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Float, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import random, httpx, uuid

DATABASE_URL = "sqlite:///./ovg.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ================= الجداول =================
class VisitModel(Base):
    __tablename__ = "visits"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    click_id = Column(String, index=True) # معرف الزيارة عشان نربطها بالتحويل
    ip = Column(String)
    user_agent = Column(String)
    zone_id = Column(String, index=True)
    score = Column(Integer)
    verdict = Column(String)
    evidence = Column(JSON)
    raw_data = Column(JSON)
    os = Column(String, default="Unknown")
    device = Column(String, default="Unknown")
    browser = Column(String, default="Unknown")
    country = Column(String, default="Unknown")
    isp = Column(String, default="Unknown")

class CostModel(Base):
    __tablename__ = "costs"
    id = Column(Integer, primary_key=True, index=True)
    zone_id = Column(String, unique=True, index=True)
    amount = Column(Float, default=0.0)

class ConversionModel(Base):
    __tablename__ = "conversions"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    click_id = Column(String, index=True)
    zone_id = Column(String, index=True)
    payout = Column(Float, default=0.0)

Base.metadata.drop_all(bind=engine) # تحديث الداتابيز
Base.metadata.create_all(bind=engine)

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

class TrackPayload(BaseModel):
    url: str
    nav: dict
    fingerprint: dict
    behavior: dict
    screen: dict = {}

class CostPayload(BaseModel):
    zone_id: str
    amount: float

ip_cache = {}

async def get_ip_info(ip: str):
    if ip in ip_cache: return ip_cache[ip]
    if ip.startswith("127.") or ip.startswith("192.168."): return ("Local", "Local ISP")
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(f"https://ipwho.is/{ip}", timeout=2.0)
            data = res.json()
            if data.get("success") is True:
                result = (data.get("country", "Unknown"), data.get("connection", {}).get("isp", "Unknown"))
                ip_cache[ip] = result
                return result
    except: pass
    return ("Unknown", "Unknown")

def parse_ua(ua: str):
    ua = ua.lower()
    device = "Mobile" if "mobi" in ua else ("Tablet" if "tablet" in ua else "Desktop")
    if "windows" in ua: os_name = "Windows"
    elif "mac os" in ua: os_name = "macOS"
    elif "android" in ua: os_name = "Android"
    elif "iphone" in ua or "ipad" in ua: os_name = "iOS"
    elif "linux" in ua: os_name = "Linux"
    else: os_name = "Unknown"
    browser = "Chrome" if "chrome" in ua else "Safari" if "safari" in ua else "Firefox" if "firefox" in ua else "Unknown"
    return os_name, device, browser

# ================= محرك الحكم (Anura Style) =================
def analyze_visit(data: dict):
    score = 0
    evidence = []
    nav = data.get("nav", {})
    screen = data.get("screen", {})
    fp = data.get("fingerprint", {})
    behavior = data.get("behavior", {})
    events = behavior.get("events", {})
    ua = str(nav.get("ua", "")).lower()

    if nav.get("webdriver") is True:
        score += 80; evidence.append("WebDriver")
    if not ua or "headless" in ua or "python" in ua or "curl" in ua:
        score += 90; evidence.append("Suspicious UA")
    if "win" in ua and "win" not in str(nav.get("platform", "")).lower():
        score += 50; evidence.append("OS Mismatch")
    if screen.get("width", 0) == 0:
        score += 40; evidence.append("Zero Screen")
    renderer = str(fp.get("webgl", {}).get("renderer", "")).lower()
    if "swiftshader" in renderer or "llvmpipe" in renderer:
        score += 60; evidence.append("Virtual Renderer")
    if behavior.get("time_on_page_ms", 0) < 1000:
        score += 40; evidence.append("Left <1s")
    if events.get("mousemove", 0) == 0 and events.get("touchstart", 0) == 0:
        score += 30; evidence.append("No Mouse/Touch")

    score = min(100, score)
    if score >= 70: verdict = "invalid"
    elif score >= 30: verdict = "suspicious"
    else: verdict = "valid"
    return {"score": score, "verdict": verdict, "evidence": evidence}

# ================= APIs =================
@app.get("/")
def read_root(): return {"status": "OVG Pro Cloaker is Live"}

@app.post("/api/track")
async def track_visit(payload: TrackPayload, request: Request):
    db = SessionLocal()
    parsed_url = urlparse(payload.url)
    params = parse_qs(parsed_url.query)
    zone_id = params.get("zoneid", ["unknown"])[0]
    
    # لو الزائر جاي بمعرف كليك (من PopAds) نستخدمه، لو لأ نعمل واحد جديد
    click_id = params.get("clickid", params.get("subid", [str(uuid.uuid4())[:8]]))[0]

    ua = payload.nav.get("ua", "")
    os_name, device, browser = parse_ua(ua)
    country, isp = await get_ip_info(request.client.host)
    result = analyze_visit(payload.dict())
    
    visit = VisitModel(
        click_id=click_id, ip=request.client.host, user_agent=ua, zone_id=zone_id,
        score=result["score"], verdict=result["verdict"], evidence=result["evidence"], raw_data=payload.dict(),
        os=os_name, device=device, browser=browser, country=country, isp=isp
    )
    db.add(visit); db.commit(); db.close()

    # شرطي المرور: لو بوت نطيره جوجل، لو بني آدم يسيب الصفحة تفتح
    if result["verdict"] == "invalid":
        return {"action": "redirect", "url": "https://www.google.com"}
    else:
        return {"action": "stay", "click_id": click_id}

# API عشان نستقبل منه الأرباح من شبكة الـ CPA (Postback)
@app.get("/api/postback")
async def postback(click_id: str, payout: float, db: Session = Depends(get_db)):
    visit = db.query(VisitModel).filter(VisitModel.click_id == click_id).first()
    if visit:
        conv = ConversionModel(click_id=click_id, zone_id=visit.zone_id, payout=payout)
        db.add(conv)
        db.commit()
        return {"status": "conversion_saved"}
    return {"status": "click_id_not_found"}

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(VisitModel).count()
    valid = db.query(VisitModel).filter(VisitModel.verdict == "valid").count()
    invalid = db.query(VisitModel).filter(VisitModel.verdict == "invalid").count()
    
    total_cost = db.query(func.sum(CostModel.amount)).scalar() or 0.0
    total_revenue = db.query(func.sum(ConversionModel.payout)).scalar() or 0.0
    profit = total_revenue - total_cost
    roi = round((profit / total_cost) * 100, 1) if total_cost > 0 else 0.0
    
    recent = db.query(VisitModel).order_by(VisitModel.id.desc()).limit(20).all()
    recent_visits = [{
        "id": v.id, "time": v.timestamp.strftime("%H:%M:%S"), "zone": v.zone_id, 
        "verdict": v.verdict, "click_id": v.click_id, "country": v.country
    } for v in recent]
    
    return {
        "total": total, "valid": valid, "invalid": invalid, 
        "total_cost": total_cost, "total_revenue": total_revenue, "profit": profit, "roi": roi,
        "recent": recent_visits
    }

@app.post("/api/cost")
def set_cost(payload: CostPayload, db: Session = Depends(get_db)):
    existing = db.query(CostModel).filter(CostModel.zone_id == payload.zone_id).first()
    if existing: existing.amount = payload.amount
    else: db.add(CostModel(zone_id=payload.zone_id, amount=payload.amount))
    db.commit(); return {"status": "success"}

@app.post("/api/mock-data")
def generate_mock(db: Session = Depends(get_db)):
    zones = ["10245", "88321", "55410"]
    for _ in range(100):
        z = random.choice(zones)
        verdict = random.choices(["valid", "invalid"], weights=[80, 20])[0]
        score = random.randint(0, 30) if verdict == "valid" else random.randint(70, 100)
        click_id = str(uuid.uuid4())[:8]
        v = VisitModel(click_id=click_id, ip="127.0.0.1", user_agent="Mock", zone_id=z, score=score, verdict=verdict, evidence=[], raw_data={})
        db.add(v)
        # لو الزيارة صالحة، نخترع ليها ربح عشان نشوف الأرقام بتتحرك
        if verdict == "valid" and random.random() > 0.8:
            db.add(ConversionModel(click_id=click_id, zone_id=z, payout=round(random.uniform(0.1, 2.0), 2)))
    db.commit(); return {"status": "ok"}

# ================= الداشبورد =================
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
    <!DOCTYPE html>
    <html lang="ar" dir="rtl">
    <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OVG Pro Cloaker</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
        <style>body{font-family:'Cairo',sans-serif;background-color:#0f172a;color:#f8fafc;}</style>
    </head>
    <body class="flex flex-col md:flex-row h-screen overflow-hidden">
        <!-- Sidebar -->
        <aside class="w-full md:w-64 bg-slate-900 border-l border-slate-700 flex flex-col shrink-0">
            <div class="p-4 text-xl font-bold text-blue-500 border-b border-slate-700">OVG Pro</div>
            <nav class="flex-1 p-2 space-y-1">
                <button onclick="switchPage('live')" class="w-full text-right px-4 py-2 rounded-lg bg-blue-600 text-white font-bold">لوحة التحكم</button>
                <button onclick="switchPage('settings')" class="w-full text-right px-4 py-2 rounded-lg text-slate-400 hover:bg-slate-800">الإعدادات</button>
            </nav>
            <div class="p-4 border-t border-slate-700">
                <button onclick="generateMock()" class="w-full bg-purple-600 py-2 rounded-lg text-sm font-bold">توليد بيانات</button>
            </div>
        </aside>

        <!-- Main Content -->
        <main class="flex-1 overflow-y-auto p-4">
            <div id="page-live" class="block">
                <h1 class="text-xl font-bold mb-4">نظرة عامة (الأرباح)</h1>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
                    <div class="bg-slate-800 p-3 rounded-lg border-t-4 border-t-blue-500"><p class="text-slate-400 text-xs">إجمالي الزيارات</p><p id="kpi-total" class="text-xl font-bold">0</p></div>
                    <div class="bg-slate-800 p-3 rounded-lg border-t-4 border-t-red-500"><p class="text-slate-400 text-xs">البوتات (اللي طارت)</p><p id="kpi-invalid" class="text-xl font-bold text-red-500">0</p></div>
                    <div class="bg-slate-800 p-3 rounded-lg border-t-4 border-t-green-500"><p class="text-slate-400 text-xs">الإيراد</p><p id="kpi-revenue" class="text-xl font-bold text-green-500">$0</p></div>
                    <div class="bg-slate-800 p-3 rounded-lg border-t-4 border-t-yellow-500"><p class="text-slate-400 text-xs">صافي الربح (ROI)</p><p id="kpi-profit" class="text-xl font-bold text-yellow-500">$0</p></div>
                </div>
                
                <div class="bg-slate-800 p-4 rounded-lg overflow-x-auto">
                    <h2 class="font-bold mb-2 text-sm">آخر الزيارات (البوتات بتروح جوجل)</h2>
                    <table class="w-full text-xs text-right">
                        <thead class="text-slate-400 border-b border-slate-700"><tr><th class="pb-2">الوقت</th><th class="pb-2">Zone</th><th class="pb-2">Click ID</th><th class="pb-2">الحكم</th></tr></thead>
                        <tbody id="live-table"></tbody>
                    </table>
                </div>
            </div>

            <div id="page-settings" class="hidden">
                <h1 class="text-xl font-bold mb-4">إعدادات التكلفة</h1>
                <div class="bg-slate-800 p-4 rounded-lg">
                    <div class="flex gap-2 mb-4">
                        <input type="text" id="cost-zone" placeholder="Zone ID" class="bg-slate-900 p-2 rounded text-white w-1/3 border border-slate-600 text-sm">
                        <input type="number" id="cost-amount" placeholder="التكلفة $" class="bg-slate-900 p-2 rounded text-white w-1/3 border border-slate-600 text-sm">
                        <button onclick="saveCost()" class="bg-blue-600 px-4 rounded font-bold w-1/3 text-sm">حفظ</button>
                    </div>
                    <p class="text-xs text-slate-400 mt-2">لإضافة ربح وهمي للتجربة، افتح الرابط ده:<br> <code class="text-green-400 select-all">/api/postback?click_id=ضع_الـ_click_id_هنا&payout=1.5</code></p>
                </div>
            </div>
        </main>

        <script>
            function switchPage(page) {
                ['live', 'settings'].forEach(p => document.getElementById('page-'+p).classList.add('hidden'));
                document.getElementById('page-'+page).classList.remove('hidden');
            }
            async function generateMock() { await fetch('/api/mock-data', {method: 'POST'}); loadLive(); }
            async function saveCost() {
                await fetch('/api/cost', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({zone_id:document.getElementById('cost-zone').value, amount:parseFloat(document.getElementById('cost-amount').value)})});
                alert("تم!"); loadLive();
            }
            async function loadLive() {
                const res = await fetch('/api/stats'); const data = await res.json();
                document.getElementById('kpi-total').innerText = data.total;
                document.getElementById('kpi-invalid').innerText = data.invalid;
                document.getElementById('kpi-revenue').innerText = '$' + data.total_revenue;
                document.getElementById('kpi-profit').innerText = '$' + data.profit + ' (' + data.roi + '%)';
                
                const tbody = document.getElementById('live-table'); tbody.innerHTML = '';
                data.recent.forEach(v => {
                    const c = v.verdict === 'valid' ? 'text-green-500' : 'text-red-500';
                    tbody.innerHTML += `<tr class="border-b border-slate-700">
                        <td class="py-2">${v.time}</td><td>${v.zone}</td><td class="text-slate-400">${v.click_id}</td>
                        <td class="${c} font-bold">${v.verdict}</td></tr>`;
                });
            }
            loadLive(); setInterval(loadLive, 15000);
        </script>
    </body>
    </html>
    """
