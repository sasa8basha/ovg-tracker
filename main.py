from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import random, httpx

DATABASE_URL = "sqlite:///./ovg.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ================= الجدول الأساسي للزيارات =================
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
    os = Column(String, default="Unknown")
    device = Column(String, default="Unknown")
    browser = Column(String, default="Unknown")
    country = Column(String, default="Unknown")
    isp = Column(String, default="Unknown")

# إنشاء الداتابيز
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

# ================= محرك التحليل =================
def analyze_visit(data: dict):
    score = 0
    evidence = []
    nav = data.get("nav", {})
    screen = data.get("screen", {})
    fp = data.get("fingerprint", {})
    behavior = data.get("behavior", {})
    events = behavior.get("events", {})
    ua = str(nav.get("ua", "")).lower()

    if nav.get("webdriver") is True: score += 80; evidence.append("WebDriver Flag")
    if not ua or "headless" in ua or "python" in ua or "curl" in ua: score += 90; evidence.append("Suspicious UA")
    if "win" in ua and "win" not in str(nav.get("platform", "")).lower(): score += 50; evidence.append("OS Mismatch")
    if screen.get("width", 0) == 0: score += 40; evidence.append("Zero Screen Size")
    renderer = str(fp.get("webgl", {}).get("renderer", "")).lower()
    if "swiftshader" in renderer or "llvmpipe" in renderer: score += 60; evidence.append("Virtual Renderer")
    if behavior.get("time_on_page_ms", 0) < 1000: score += 40; evidence.append("Left <1s")
    if events.get("mousemove", 0) == 0 and events.get("touchstart", 0) == 0: score += 30; evidence.append("No Interaction")

    score = min(100, score)
    if score >= 70: verdict = "invalid"
    elif score >= 30: verdict = "suspicious"
    else: verdict = "valid"
    return {"score": score, "verdict": verdict, "evidence": evidence}

# ================= APIs =================
@app.get("/")
def read_root(): return {"status": "OVG Server is Running"}

@app.post("/api/track")
async def track_visit(payload: TrackPayload, request: Request):
    db = SessionLocal()
    parsed_url = urlparse(payload.url)
    zone_id = parse_qs(parsed_url.query).get("zoneid", ["unknown"])[0]
    ua = payload.nav.get("ua", "")
    os_name, device, browser = parse_ua(ua)
    country, isp = await get_ip_info(request.client.host)
    result = analyze_visit(payload.dict())
    
    visit = VisitModel(
        ip=request.client.host, user_agent=ua, zone_id=zone_id,
        score=result["score"], verdict=result["verdict"], evidence=result["evidence"],
        os=os_name, device=device, browser=browser, country=country, isp=isp
    )
    db.add(visit); db.commit(); db.close()
    return {"status": "success"}

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(VisitModel).count()
    valid = db.query(VisitModel).filter(VisitModel.verdict == "valid").count()
    invalid = db.query(VisitModel).filter(VisitModel.verdict == "invalid").count()
    suspicious = db.query(VisitModel).filter(VisitModel.verdict == "suspicious").count()
    
    recent = db.query(VisitModel).order_by(VisitModel.id.desc()).limit(15).all()
    recent_visits = [{
        "time": v.timestamp.strftime("%H:%M:%S"), "zone": v.zone_id, "verdict": v.verdict,
        "country": v.country, "device": v.device, "os": v.os
    } for v in recent]
    
    return {"total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious, "recent": recent_visits}

@app.get("/api/reports/zones")
def get_zone_reports(db: Session = Depends(get_db)):
    zones = db.query(
        VisitModel.zone_id, 
        func.count(VisitModel.id).label('total'),
        func.sum(func.iif(VisitModel.verdict == 'invalid', 1, 0)).label('invalid')
    ).group_by(VisitModel.zone_id).all()
    
    report = []
    for z in zones:
        total = z.total; invalid = z.invalid or 0
        bot_rate = round((invalid / total) * 100, 1) if total > 0 else 0
        grade = "A" if bot_rate < 5 else "B" if bot_rate < 15 else "C" if bot_rate < 30 else "F"
        report.append({"zone": z.zone_id, "total": total, "bot_rate": bot_rate, "grade": grade})
    report.sort(key=lambda x: x['bot_rate'], reverse=True)
    return report

@app.post("/api/mock-data")
def generate_mock(db: Session = Depends(get_db)):
    zones = ["10245", "88321", "55410", "99120"]
    countries = ["US", "UK", "EG", "SA"]
    for _ in range(150):
        z = random.choice(zones)
        verdict = random.choices(["valid", "invalid", "suspicious"], weights=[75, 20, 5])[0]
        score = random.randint(0, 30) if verdict == "valid" else random.randint(70, 100) if verdict == "invalid" else random.randint(30, 69)
        v = VisitModel(ip="127.0.0.1", user_agent="Mock", zone_id=z, score=score, verdict=verdict, evidence=["Mock"], 
                       os=random.choice(["Windows", "Android", "iOS"]), device=random.choice(["Desktop", "Mobile"]), 
                       browser="Chrome", country=random.choice(countries), isp="Mock ISP")
        db.add(v)
    db.commit(); return {"status": "ok"}

# ================= الداشبورد (تصميم جديد Light Theme) =================
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
    <!DOCTYPE html>
    <html lang="ar" dir="rtl">
    <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OVG Analytics</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
        <style>body { font-family: 'Cairo', sans-serif; background-color: #f8fafc; color: #1e293b; }</style>
    </head>
    <body class="flex h-screen overflow-hidden">
        
        <!-- Sidebar (Light Theme) -->
        <aside class="w-64 bg-white border-l border-slate-200 hidden md:flex flex-col shadow-sm">
            <div class="p-6 text-2xl font-bold text-indigo-600 border-b border-slate-100">OVG Analytics</div>
            <nav class="flex-1 p-4 space-y-2">
                <button onclick="switchPage('dashboard')" class="w-full text-right px-4 py-3 rounded-xl bg-indigo-50 text-indigo-700 font-bold transition">لوحة التحكم</button>
                <button onclick="switchPage('zones')" class="w-full text-right px-4 py-3 rounded-xl text-slate-500 hover:bg-slate-50 hover:text-slate-800 font-semibold transition">تقارير الزونات</button>
            </nav>
            <div class="p-4 border-t border-slate-100">
                <button onclick="generateMock()" class="w-full bg-indigo-600 hover:bg-indigo-700 text-white py-2.5 rounded-xl text-sm font-bold shadow-md shadow-indigo-200 transition">توليد بيانات تجريبية</button>
            </div>
        </aside>

        <!-- Main Content -->
        <main class="flex-1 overflow-y-auto p-4 md:p-8">
            
            <!-- Page: Dashboard -->
            <div id="page-dashboard" class="block">
                <h1 class="text-2xl font-bold mb-6 text-slate-800">نظرة عامة</h1>
                
                <!-- KPI Cards -->
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                    <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100">
                        <p class="text-slate-500 text-sm font-semibold mb-1">إجمالي الزيارات</p>
                        <p id="kpi-total" class="text-3xl font-bold text-slate-800">0</p>
                    </div>
                    <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100 border-r-4 border-r-emerald-500">
                        <p class="text-slate-500 text-sm font-semibold mb-1">زيارات صالحة</p>
                        <p id="kpi-valid" class="text-3xl font-bold text-emerald-600">0</p>
                    </div>
                    <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100 border-r-4 border-r-rose-500">
                        <p class="text-slate-500 text-sm font-semibold mb-1">بوتات (Invalid)</p>
                        <p id="kpi-invalid" class="text-3xl font-bold text-rose-600">0</p>
                    </div>
                    <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100 border-r-4 border-r-amber-500">
                        <p class="text-slate-500 text-sm font-semibold mb-1">مشبوهة</p>
                        <p id="kpi-suspicious" class="text-3xl font-bold text-amber-500">0</p>
                    </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <!-- Chart -->
                    <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-100 col-span-1">
                        <h2 class="text-sm font-bold text-slate-700 mb-4">نسبة جودة الترافيك</h2>
                        <div class="relative h-48 flex justify-center">
                            <canvas id="qualityChart"></canvas>
                        </div>
                    </div>
                    
                    <!-- Live Table -->
                    <div class="bg-white rounded-2xl shadow-sm border border-slate-100 col-span-1 md:col-span-2 overflow-hidden">
                        <div class="p-5 border-b border-slate-100"><h2 class="text-sm font-bold text-slate-700">أحدث الزيارات (Live)</h2></div>
                        <div class="overflow-x-auto">
                            <table class="w-full text-sm text-right">
                                <thead class="text-xs text-slate-400 bg-slate-50">
                                    <tr><th class="px-4 py-3">الوقت</th><th class="px-4 py-3">الزون</th><th class="px-4 py-3">الدولة</th><th class="px-4 py-3">الحكم</th></tr>
                                </thead>
                                <tbody id="live-table" class="divide-y divide-slate-100"></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Page: Zones -->
            <div id="page-zones" class="hidden">
                <h1 class="text-2xl font-bold mb-6 text-slate-800">تقارير الزونات</h1>
                <div class="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden">
                    <table class="w-full text-sm text-right">
                        <thead class="bg-slate-50 text-slate-400 text-xs">
                            <tr><th class="px-5 py-4">Zone ID</th><th class="px-5 py-4">الزيارات</th><th class="px-5 py-4">نسبة البوتات</th><th class="px-5 py-4">التقييم</th></tr>
                        </thead>
                        <tbody id="zones-table" class="divide-y divide-slate-100"></tbody>
                    </table>
                </div>
            </div>

        </main>

        <script>
            let chartInstance = null;
            function switchPage(page) {
                document.getElementById('page-dashboard').classList.add('hidden');
                document.getElementById('page-zones').classList.add('hidden');
                document.getElementById('page-'+page).classList.remove('hidden');
                if(page === 'zones') loadZones();
            }

            async function generateMock() {
                await fetch('/api/mock-data', {method: 'POST'}); 
                loadData();
            }

            async function loadData() {
                const res = await fetch('/api/stats'); const data = await res.json();
                document.getElementById('kpi-total').innerText = data.total;
                document.getElementById('kpi-valid').innerText = data.valid;
                document.getElementById('kpi-invalid').innerText = data.invalid;
                document.getElementById('kpi-suspicious').innerText = data.suspicious;

                // Live Table
                const tbody = document.getElementById('live-table'); tbody.innerHTML = '';
                data.recent.forEach(v => {
                    const badge = v.verdict === 'valid' ? 'bg-emerald-100 text-emerald-700' : v.verdict === 'invalid' ? 'bg-rose-100 text-rose-700' : 'bg-amber-100 text-amber-700';
                    tbody.innerHTML += `<tr class="hover:bg-slate-50 transition">
                        <td class="px-4 py-3 text-slate-500">${v.time}</td>
                        <td class="px-4 py-3 font-semibold">${v.zone}</td>
                        <td class="px-4 py-3 text-slate-500">${v.country}</td>
                        <td class="px-4 py-3"><span class="${badge} px-2.5 py-1 rounded-md text-xs font-bold">${v.verdict}</span></td>
                    </tr>`;
                });

                // Chart
                if (chartInstance) chartInstance.destroy();
                const ctx = document.getElementById('qualityChart').getContext('2d');
                chartInstance = new Chart(ctx, {
                    type: 'doughnut',
                    data: { labels: ['Valid', 'Invalid', 'Suspicious'], datasets: [{ data: [data.valid, data.invalid, data.suspicious], backgroundColor: ['#10b981', '#f43f5e', '#f59e0b'], borderWidth: 0 }] },
                    options: { cutout: '75%', plugins: { legend: { position: 'bottom', labels: { usePointStyle: true, boxWidth: 8, font: {size: 11} } } } }
                });
            }

            async function loadZones() {
                const res = await fetch('/api/reports/zones'); const data = await res.json();
                const tbody = document.getElementById('zones-table'); tbody.innerHTML = '';
                data.forEach(z => {
                    const gradeColor = z.grade === 'A' ? 'bg-indigo-100 text-indigo-700' : z.grade === 'F' ? 'bg-rose-100 text-rose-700' : 'bg-slate-100 text-slate-700';
                    tbody.innerHTML += `<tr class="hover:bg-slate-50 transition">
                        <td class="px-5 py-4 font-bold text-slate-700">${z.zone}</td>
                        <td class="px-5 py-4 text-slate-600">${z.total}</td>
                        <td class="px-5 py-4"><span class="${z.bot_rate > 30 ? 'text-rose-600 font-bold' : 'text-slate-600'}">${z.bot_rate}%</span></td>
                        <td class="px-5 py-4"><span class="${gradeColor} px-3 py-1 rounded-lg text-xs font-bold">${z.grade}</span></td>
                    </tr>`;
                });
            }

            loadData(); setInterval(loadData, 15000);
        </script>
    </body>
    </html>
    """
