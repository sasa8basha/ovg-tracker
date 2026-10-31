from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, PlainTextResponse
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Float, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import random, io, csv, httpx, json

DATABASE_URL = "sqlite:///./ovg.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ================= الجداول =================
class VisitModel(Base):
    __tablename__ = "visits"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
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

# مسح الجدول القديم عشان نضيف الأعمدة الجديدة ونبني من جديد
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# دالة استقبال البيانات (مرنة عشان متضربش خطأ)
class TrackPayload(BaseModel):
    url: str
    nav: dict
    fingerprint: dict
    behavior: dict
    screen: dict = {}
    extras: dict = {}

class CostPayload(BaseModel):
    zone_id: str
    amount: float

ip_cache = {}

async def get_ip_info(ip: str):
    if ip in ip_cache: return ip_cache[ip]
    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
        return ("Local", "Local ISP")
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

# ================= محرك التحليل الجنائي =================
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
        score += 80; evidence.append("WebDriver Flag True")
    
    if not ua or "headless" in ua or "python" in ua or "curl" in ua or "bot" in ua:
        score += 90; evidence.append("Suspicious User-Agent")

    platform = str(nav.get("platform", "")).lower()
    if "win" in ua and "win" not in platform:
        score += 50; evidence.append("OS Mismatch (UA vs Platform)")

    if screen.get("width", 0) == 0 or screen.get("height", 0) == 0:
        score += 40; evidence.append("Zero Screen Size")

    renderer = str(fp.get("webgl", {}).get("renderer", "")).lower()
    if "swiftshader" in renderer or "llvmpipe" in renderer or "virtualbox" in renderer:
        score += 60; evidence.append("Virtual/Software Renderer")

    tom = behavior.get("time_on_page_ms", 0)
    if tom < 1000:
        score += 40; evidence.append("Left immediately (<1s)")
    if events.get("mousemove", 0) == 0 and events.get("touchstart", 0) == 0:
        score += 30; evidence.append("No Mouse/Touch")

    if nav.get("hardwareConcurrency", 0) < 2 and nav.get("hardwareConcurrency", 0) != 0:
        score += 20; evidence.append("Low CPU Cores")

    score = min(100, score)
    if score >= 70: verdict = "invalid"
    elif score >= 30: verdict = "suspicious"
    else: verdict = "valid"
    return {"score": score, "verdict": verdict, "evidence": evidence}

# ================= APIs =================
@app.get("/")
def read_root(): return {"status": "OVG Pro Server is Live"}

@app.post("/api/track")
async def track_visit(payload: TrackPayload, request: Request):
    db = SessionLocal()
    zone_id = parse_qs(urlparse(payload.url).query).get("zoneid", ["unknown"])[0]
    
    ua = payload.nav.get("ua", "")
    os_name, device, browser = parse_ua(ua)
    country, isp = await get_ip_info(request.client.host)
    result = analyze_visit(payload.dict())
    
    visit = VisitModel(
        ip=request.client.host, user_agent=ua, zone_id=zone_id,
        score=result["score"], verdict=result["verdict"], evidence=result["evidence"], raw_data=payload.dict(),
        os=os_name, device=device, browser=browser, country=country, isp=isp
    )
    db.add(visit); db.commit(); db.close()
    return {"status": "success"}

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(VisitModel).count()
    valid = db.query(VisitModel).filter(VisitModel.verdict == "valid").count()
    invalid = db.query(VisitModel).filter(VisitModel.verdict == "invalid").count()
    total_cost = db.query(func.sum(CostModel.amount)).scalar() or 0.0
    
    recent = db.query(VisitModel).order_by(VisitModel.id.desc()).limit(20).all()
    recent_visits = [{
        "id": v.id, "time": v.timestamp.strftime("%H:%M:%S"), "zone": v.zone_id, "verdict": v.verdict, 
        "country": v.country, "isp": v.isp
    } for v in recent]
    return {"total": total, "valid": valid, "invalid": invalid, "total_cost": total_cost, "recent": recent_visits}

@app.get("/api/visit/{visit_id}")
def get_visit_details(visit_id: int, db: Session = Depends(get_db)):
    v = db.query(VisitModel).filter(VisitModel.id == visit_id).first()
    if not v: return {"error": "Not found"}
    return {
        "id": v.id, "zone": v.zone_id, "score": v.score, "verdict": v.verdict, 
        "evidence": v.evidence, "raw_data": v.raw_data, "country": v.country, "isp": v.isp,
        "os": v.os, "device": v.device, "browser": v.browser
    }

@app.get("/api/reports/zones")
def get_zone_reports(db: Session = Depends(get_db)):
    zones = db.query(VisitModel.zone_id, func.count(VisitModel.id).label('total'),
        func.sum(func.iif(VisitModel.verdict == 'invalid', 1, 0)).label('invalid')).group_by(VisitModel.zone_id).all()
    report = []
    for z in zones:
        total = z.total; invalid = z.invalid or 0
        bot_rate = round((invalid / total) * 100, 1) if total > 0 else 0
        grade = "A+" if bot_rate < 5 else "B" if bot_rate < 15 else "C" if bot_rate < 30 else "F"
        report.append({"zone": z.zone_id, "total": total, "bot_rate": bot_rate, "grade": grade})
    report.sort(key=lambda x: x['bot_rate'], reverse=True)
    return report

@app.post("/api/mock-data")
def generate_mock(db: Session = Depends(get_db)):
    zones = ["10245", "88321", "55410", "99120"]
    for _ in range(100):
        z = random.choice(zones)
        verdict = random.choices(["valid", "invalid"], weights=[75, 25])[0]
        score = random.randint(0, 30) if verdict == "valid" else random.randint(70, 100)
        ev = ["Clean"] if verdict == "valid" else ["WebDriver", "Virtual Renderer"]
        v = VisitModel(ip="127.0.0.1", user_agent="Mock", zone_id=z, score=score, verdict=verdict, evidence=ev, raw_data={"mock": True}, 
                       os="Android", device="Mobile", browser="Chrome", country="Egypt", isp="Vodafone")
        db.add(v)
    db.commit(); return {"status": "ok"}

# ================= الداشبورد =================
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
    <!DOCTYPE html>
    <html lang="ar" dir="rtl">
    <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OVG Pro Forensics</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
        <style>body{font-family:'Cairo',sans-serif;background-color:#0f172a;color:#f8fafc;}</style>
    </head>
    <body class="flex flex-col md:flex-row h-screen overflow-hidden">
        <!-- Sidebar -->
        <aside class="w-full md:w-64 bg-slate-900 border-l border-slate-700 flex flex-col shrink-0">
            <div class="p-4 text-xl font-bold text-blue-500 border-b border-slate-700">OVG Pro</div>
            <nav class="flex-1 p-2 space-y-1 overflow-y-auto">
                <button onclick="switchPage('live')" class="w-full text-right px-4 py-2 rounded-lg bg-blue-600 text-white font-bold">لوحة التحكم</button>
                <button onclick="switchPage('forensics')" class="w-full text-right px-4 py-2 rounded-lg text-slate-400 hover:bg-slate-800">التحليل الجنائي</button>
                <button onclick="switchPage('zones')" class="w-full text-right px-4 py-2 rounded-lg text-slate-400 hover:bg-slate-800">تقارير الـ Zones</button>
            </nav>
            <div class="p-4 border-t border-slate-700">
                <button onclick="generateMock()" class="w-full bg-purple-600 py-2 rounded-lg text-sm font-bold">توليد بيانات</button>
            </div>
        </aside>

        <!-- Main Content -->
        <main class="flex-1 overflow-y-auto p-4">
            <div id="page-live" class="block">
                <h1 class="text-xl font-bold mb-4">نظرة عامة</h1>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
                    <div class="bg-slate-800 p-3 rounded-lg border-t-4 border-t-blue-500"><p class="text-slate-400 text-xs">إجمالي</p><p id="kpi-total" class="text-xl font-bold">0</p></div>
                    <div class="bg-slate-800 p-3 rounded-lg border-t-4 border-t-green-500"><p class="text-slate-400 text-xs">صالحة</p><p id="kpi-valid" class="text-xl font-bold text-green-500">0</p></div>
                    <div class="bg-slate-800 p-3 rounded-lg border-t-4 border-t-red-500"><p class="text-slate-400 text-xs">بوتات</p><p id="kpi-invalid" class="text-xl font-bold text-red-500">0</p></div>
                    <div class="bg-slate-800 p-3 rounded-lg border-t-4 border-t-yellow-500"><p class="text-slate-400 text-xs">التكلفة</p><p id="kpi-cost" class="text-xl font-bold text-yellow-500">$0</p></div>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div class="bg-slate-800 p-4 rounded-lg col-span-1"><canvas id="verdictChart"></canvas></div>
                    <div class="bg-slate-800 p-4 rounded-lg col-span-1 md:col-span-2 overflow-x-auto">
                        <h2 class="font-bold mb-2 text-sm">آخر الزيارات (دوس على أي زيارة للتحليل)</h2>
                        <table class="w-full text-xs text-right">
                            <thead class="text-slate-400 border-b border-slate-700"><tr><th class="pb-2">الوقت</th><th class="pb-2">Zone</th><th class="pb-2">الحكم</th></tr></thead>
                            <tbody id="live-table"></tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div id="page-forensics" class="hidden">
                <h1 class="text-xl font-bold mb-4">التحليل الجنائي</h1>
                <div id="forensics-content" class="bg-slate-800 p-4 rounded-lg border border-slate-700">
                    <p class="text-slate-400">اختر زيارة من لوحة التحكم لعرض تفاصيلها.</p>
                </div>
            </div>

            <div id="page-zones" class="hidden">
                <h1 class="text-xl font-bold mb-4">تقارير الـ Zones</h1>
                <div class="bg-slate-800 rounded-lg overflow-x-auto">
                    <table class="w-full text-xs text-right">
                        <thead class="bg-slate-900 text-slate-400"><tr><th class="p-2">Zone</th><th class="p-2">الإجمالي</th><th class="p-2">البوتات %</th><th class="p-2">التقييم</th></tr></thead>
                        <tbody id="zones-table"></tbody>
                    </table>
                </div>
            </div>
        </main>

        <script>
            let chartInstance = null;
            function switchPage(page) {
                ['live', 'forensics', 'zones'].forEach(p => document.getElementById('page-'+p).classList.add('hidden'));
                document.getElementById('page-'+page).classList.remove('hidden');
                if(page === 'zones') loadZones();
            }
            async function generateMock() { await fetch('/api/mock-data', {method: 'POST'}); loadLive(); }
            async function loadLive() {
                const res = await fetch('/api/stats'); const data = await res.json();
                document.getElementById('kpi-total').innerText = data.total;
                document.getElementById('kpi-valid').innerText = data.valid;
                document.getElementById('kpi-invalid').innerText = data.invalid;
                document.getElementById('kpi-cost').innerText = '$' + data.total_cost;
                const tbody = document.getElementById('live-table'); tbody.innerHTML = '';
                data.recent.forEach(v => {
                    const c = v.verdict === 'valid' ? 'text-green-500' : 'text-red-500';
                    tbody.innerHTML += `<tr class="border-b border-slate-700 hover:bg-slate-700 cursor-pointer" onclick="showForensics(${v.id})">
                        <td class="py-2">${v.time}</td><td>${v.zone}</td><td class="${c} font-bold">${v.verdict}</td></tr>`;
                });
                if (chartInstance) chartInstance.destroy();
                const ctx = document.getElementById('verdictChart').getContext('2d');
                chartInstance = new Chart(ctx, {
                    type: 'doughnut',
                    data: { labels: ['Valid', 'Invalid'], datasets: [{ data: [data.valid, data.invalid], backgroundColor: ['#22c55e', '#ef4444'], borderWidth: 0 }] },
                    options: { cutout: '70%', plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } } }
                });
            }
            async function showForensics(id) {
                switchPage('forensics');
                const res = await fetch('/api/visit/' + id); const v = await res.json();
                const raw = JSON.stringify(v.raw_data, null, 2);
                const ev = v.evidence.map(e => `<li class="text-red-400">${e}</li>`).join('');
                document.getElementById('forensics-content').innerHTML = `
                    <div class="grid grid-cols-2 gap-2 mb-4 text-sm">
                        <div><span class="text-slate-400">الحكم:</span> <span class="${v.verdict === 'valid' ? 'text-green-500' : 'text-red-500'} font-bold text-lg">${v.verdict.toUpperCase()}</span></div>
                        <div><span class="text-slate-400">السكور:</span> <span class="font-bold text-lg">${v.score}/100</span></div>
                        <div><span class="text-slate-400">Zone:</span> ${v.zone}</div>
                        <div><span class="text-slate-400">البلد:</span> ${v.country}</div>
                    </div>
                    <h3 class="font-bold mb-2 text-sm">الأسباب:</h3>
                    <ul class="list-disc list-inside mb-4 bg-slate-900 p-2 rounded-lg text-xs">${ev || '<li class="text-green-400">مفيش اشتباه</li>'}</ul>
                    <h3 class="font-bold mb-2 text-sm">البيانات الخام:</h3>
                    <pre class="bg-slate-900 p-2 rounded-lg text-[10px] overflow-x-auto text-green-300">${raw}</pre>
                `;
            }
            async function loadZones() {
                const res = await fetch('/api/reports/zones'); const data = await res.json();
                const tbody = document.getElementById('zones-table'); tbody.innerHTML = '';
                data.forEach(z => {
                    const gc = z.grade === 'A+' ? 'bg-green-500 text-black' : z.grade === 'F' ? 'bg-red-500' : 'bg-yellow-500 text-black';
                    tbody.innerHTML += `<tr class="border-b border-slate-700"><td class="p-2 font-bold text-blue-400">${z.zone}</td><td class="p-2">${z.total}</td><td class="p-2">${z.bot_rate}%</td><td class="p-2"><span class="${gc} px-2 py-1 rounded font-bold text-[10px]">${z.grade}</span></td></tr>`;
                });
            }
            loadLive(); setInterval(loadLive, 15000);
        </script>
    </body>
    </html>
    """
