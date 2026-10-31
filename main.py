from fastapi import FastAPI, Request, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, PlainTextResponse
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Float, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
import random
import io
import csv
import re

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
    device = Column(String, default="Desktop")
    browser = Column(String, default="Unknown")

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

class TrackPayload(BaseModel):
    url: str
    nav: dict
    fingerprint: dict
    behavior: dict

class CostPayload(BaseModel):
    zone_id: str
    amount: float

# ================= محرك تحليل الـ User-Agent =================
def parse_ua(ua: str):
    ua = ua.lower()
    device = "Mobile" if "mobi" in ua else ("Tablet" if "tablet" in ua else "Desktop")
    
    if "windows" in ua: os_name = "Windows"
    elif "mac os" in ua: os_name = "macOS"
    elif "android" in ua: os_name = "Android"
    elif "iphone" in ua or "ipad" in ua: os_name = "iOS"
    elif "linux" in ua: os_name = "Linux"
    else: os_name = "Unknown"

    if "chrome" in ua and "edg" not in ua: browser = "Chrome"
    elif "safari" in ua and "chrome" not in ua: browser = "Safari"
    elif "firefox" in ua: browser = "Firefox"
    elif "edg" in ua: browser = "Edge"
    elif "opera" in ua or "opr" in ua: browser = "Opera"
    else: browser = "Unknown"
    
    return os_name, device, browser

# ================= محرك الحكم =================
def analyze_visit(data: dict):
    score = 0
    evidence = []
    nav = data.get("nav", {})
    fp = data.get("fingerprint", {})
    behavior = data.get("behavior", {})
    
    if nav.get("webdriver") is True:
        score += 80
        evidence.append("WebDriver")
    ua = nav.get("ua", "").lower()
    if not ua or "headless" in ua or "python" in ua or "curl" in ua:
        score += 90
        evidence.append("Suspicious UA")
    tom = behavior.get("time_on_page_ms", 0)
    if tom < 1500:
        score += 40
        evidence.append(f"Time {tom}ms")
    if behavior.get("events", {}).get("mousemove", 0) == 0 and nav.get("touch") is False:
        score += 30
        evidence.append("No Mouse")
    renderer = str(fp.get("webgl", {}).get("renderer", "")).lower()
    if "swiftshader" in renderer or "llvmpipe" in renderer:
        score += 50
        evidence.append("Virtual Renderer")

    score = min(100, score)
    if score >= 70: verdict = "invalid"
    elif score >= 30: verdict = "suspicious"
    else: verdict = "valid"
    return {"score": score, "verdict": verdict, "evidence": evidence}

# ================= APIs =================
@app.get("/")
def read_root(): return {"status": "OVG Server Pro"}

@app.post("/api/track")
async def track_visit(payload: TrackPayload, request: Request):
    db = SessionLocal()
    parsed_url = urlparse(payload.url)
    zone_id = parse_qs(parsed_url.query).get("zoneid", ["unknown"])[0]
    
    ua = payload.nav.get("ua", "")
    os_name, device, browser = parse_ua(ua)
    
    result = analyze_visit(payload.dict())
    
    visit = VisitModel(
        ip=request.client.host, user_agent=ua, zone_id=zone_id,
        score=result["score"], verdict=result["verdict"], evidence=result["evidence"], raw_data=payload.dict(),
        os=os_name, device=device, browser=browser
    )
    db.add(visit)
    db.commit()
    db.close()
    return {"status": "success"}

@app.get("/api/stats")
def get_stats(
    db: Session = Depends(get_db),
    zone: str = None, device: str = None, 
    start_date: str = None, end_date: str = None
):
    query = db.query(VisitModel)
    
    if zone: query = query.filter(VisitModel.zone_id == zone)
    if device: query = query.filter(VisitModel.device == device)
    if start_date: query = query.filter(VisitModel.timestamp >= start_date)
    if end_date: query = query.filter(VisitModel.timestamp <= end_date + " 23:59:59")
    
    total = query.count()
    valid = query.filter(VisitModel.verdict == "valid").count()
    invalid = query.filter(VisitModel.verdict == "invalid").count()
    suspicious = query.filter(VisitModel.verdict == "suspicious").count()
    
    # حساب التكلفة
    total_cost = db.query(func.sum(CostModel.amount)).scalar() or 0.0
    
    recent = query.order_by(VisitModel.id.desc()).limit(50).all()
    recent_visits = [{
        "time": v.timestamp.strftime("%H:%M:%S"), "zone": v.zone_id, 
        "score": v.score, "verdict": v.verdict, "device": v.device, "os": v.os,
        "evidence": ", ".join(v.evidence) if v.evidence else "طبيعي"
    } for v in recent]
    
    return {
        "total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious, 
        "total_cost": total_cost, "recent": recent_visits
    }

@app.get("/api/reports/zones")
def get_zone_reports(db: Session = Depends(get_db)):
    zones = db.query(
        VisitModel.zone_id,
        func.count(VisitModel.id).label('total'),
        func.sum(func.iif(VisitModel.verdict == 'valid', 1, 0)).label('valid'),
        func.sum(func.iif(VisitModel.verdict == 'invalid', 1, 0)).label('invalid')
    ).group_by(VisitModel.zone_id).all()
    
    costs = {c.zone_id: c.amount for c in db.query(CostModel).all()}
    
    report = []
    for z in zones:
        total = z.total
        valid = z.valid or 0
        invalid = z.invalid or 0
        bot_rate = round((invalid / total) * 100, 1) if total > 0 else 0
        report.append({
            "zone": z.zone_id, "total": total, "valid": valid, "invalid": invalid, 
            "bot_rate": bot_rate, "cost": costs.get(z.zone_id, 0.0)
        })
    report.sort(key=lambda x: x['bot_rate'], reverse=True)
    return report

@app.post("/api/cost")
def set_cost(payload: CostPayload, db: Session = Depends(get_db)):
    existing = db.query(CostModel).filter(CostModel.zone_id == payload.zone_id).first()
    if existing:
        existing.amount = payload.amount
    else:
        db.add(CostModel(zone_id=payload.zone_id, amount=payload.amount))
    db.commit()
    return {"status": "success"}

@app.get("/api/export/csv")
def export_csv(db: Session = Depends(get_db)):
    visits = db.query(VisitModel).order_by(VisitModel.id.desc()).limit(5000).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Time", "Zone", "Device", "OS", "Browser", "Verdict", "Score", "Evidence"])
    for v in visits:
        writer.writerow([v.timestamp, v.zone_id, v.device, v.os, v.browser, v.verdict, v.score, ", ".join(v.evidence) if v.evidence else ""])
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=ovg_report.csv"})

@app.get("/api/export/blacklist")
def export_blacklist(db: Session = Depends(get_db)):
    zones = db.query(
        VisitModel.zone_id,
        func.count(VisitModel.id).label('total'),
        func.sum(func.iif(VisitModel.verdict == 'invalid', 1, 0)).label('invalid')
    ).group_by(VisitModel.zone_id).all()
    
    bad_zones = []
    for z in zones:
        if z.total > 5 and (z.invalid / z.total) > 0.3: # لو نسبة البوتس عدت 30% والزيارات أكبر من 5
            bad_zones.append(str(z.zone_id))
    
    content = "\n".join(bad_zones)
    return PlainTextResponse(content, headers={"Content-Disposition": "attachment; filename=blacklist.txt"})

@app.post("/api/mock-data")
def generate_mock(db: Session = Depends(get_db)):
    zones = ["10245", "88321", "55410", "99120", "33215"]
    devices = ["Mobile", "Desktop", "Tablet"]
    os_list = ["Android", "Windows", "iOS", "Linux"]
    for _ in range(500): # 500 زيارة وهمية
        z = random.choice(zones)
        verdict = random.choices(["valid", "invalid", "suspicious"], weights=[70, 20, 10])[0]
        score = random.randint(0, 30) if verdict == "valid" else (random.randint(70, 100) if verdict == "invalid" else random.randint(30, 69))
        ev = ["طبيعي"] if verdict == "valid" else ["WebDriver"] if verdict == "invalid" else ["Time short"]
        v = VisitModel(ip="127.0.0.1", user_agent="Mock", zone_id=z, score=score, verdict=verdict, evidence=ev, raw_data={}, os=random.choice(os_list), device=random.choice(devices), browser="Chrome")
        db.add(v)
    db.commit()
    return {"status": "ok"}

# ================= الداشبورد =================
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
    <!DOCTYPE html>
    <html lang="ar" dir="rtl">
    <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OVG Pro</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
        <style>body{font-family:'Cairo',sans-serif;background-color:#0f172a;color:#f8fafc;}</style>
    </head>
    <body class="p-2 md:p-6 pb-20">
        <div class="max-w-7xl mx-auto">
            <!-- Header & Filters -->
            <div class="bg-slate-800 p-4 rounded-xl border border-slate-700 mb-6 shadow-lg">
                <div class="flex justify-between items-center mb-4">
                    <h1 class="text-xl md:text-2xl font-bold text-blue-500">OVG Pro Reports</h1>
                    <div class="flex gap-2">
                        <a href="/api/export/csv" class="bg-green-600 px-3 py-1.5 rounded text-xs md:text-sm text-white">تصدير CSV</a>
                        <a href="/api/export/blacklist" class="bg-red-600 px-3 py-1.5 rounded text-xs md:text-sm text-white">تحميل البلاك ليست</a>
                    </div>
                </div>
                <!-- Filters -->
                <div class="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm">
                    <input type="date" id="filter-start" class="bg-slate-900 p-2 rounded text-white border border-slate-600">
                    <input type="date" id="filter-end" class="bg-slate-900 p-2 rounded text-white border border-slate-600">
                    <select id="filter-device" class="bg-slate-900 p-2 rounded text-white border border-slate-600">
                        <option value="">كل الأجهزة</option>
                        <option value="Mobile">موبايل</option>
                        <option value="Desktop">كمبيوتر</option>
                    </select>
                    <input type="text" id="filter-zone" placeholder="رقم الـ Zone" class="bg-slate-900 p-2 rounded text-white border border-slate-600">
                </div>
                <div class="mt-3 flex gap-2">
                    <button onclick="applyFilters()" class="flex-1 bg-blue-600 py-2 rounded font-bold text-sm">تطبيق الفلتر</button>
                    <button onclick="resetFilters()" class="flex-1 bg-slate-600 py-2 rounded font-bold text-sm">مسح</button>
                </div>
            </div>

            <!-- KPIs -->
            <div class="grid grid-cols-2 md:grid-cols-4 gap-2 mb-6">
                <div class="bg-slate-800 p-4 rounded-xl border-t-4 border-t-blue-500">
                    <p class="text-slate-400 text-xs">إجمالي</p><p id="kpi-total" class="text-xl font-bold">0</p>
                </div>
                <div class="bg-slate-800 p-4 rounded-xl border-t-4 border-t-green-500">
                    <p class="text-slate-400 text-xs">صالحة</p><p id="kpi-valid" class="text-xl font-bold text-green-500">0</p>
                </div>
                <div class="bg-slate-800 p-4 rounded-xl border-t-4 border-t-red-500">
                    <p class="text-slate-400 text-xs">بوتات</p><p id="kpi-invalid" class="text-xl font-bold text-red-500">0</p>
                </div>
                <div class="bg-slate-800 p-4 rounded-xl border-t-4 border-t-yellow-500">
                    <p class="text-slate-400 text-xs">التكلفة الكلية</p><p id="kpi-cost" class="text-xl font-bold text-yellow-500">$0</p>
                </div>
            </div>

            <!-- Tabs -->
            <div class="flex border-b border-slate-700 mb-4 text-sm md:text-base overflow-x-auto">
                <button id="tab-btn-live" onclick="switchTab('live')" class="px-4 py-2 text-blue-500 border-b-2 border-blue-500 font-bold whitespace-nowrap">Live</button>
                <button id="tab-btn-reports" onclick="switchTab('reports')" class="px-4 py-2 text-slate-400 font-bold whitespace-nowrap">تقارير الـ Zones</button>
                <button id="tab-btn-costs" onclick="switchTab('costs')" class="px-4 py-2 text-slate-400 font-bold whitespace-nowrap">إدارة التكلفة</button>
            </div>

            <!-- Tab: Live -->
            <div id="tab-live" class="block">
                <div class="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
                    <table class="w-full text-xs text-right">
                        <thead class="bg-slate-900 text-slate-400"><tr><th class="p-3">الوقت</th><th class="p-3">Zone</th><th class="p-3">الجهاز</th><th class="p-3">الحكم</th></tr></thead>
                        <tbody id="live-table" class="divide-y divide-slate-700"></tbody>
                    </table>
                </div>
            </div>

            <!-- Tab: Reports -->
            <div id="tab-reports" class="hidden">
                <div class="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
                    <table class="w-full text-xs md:text-sm text-right">
                        <thead class="bg-slate-900 text-slate-400">
                            <tr><th class="p-3">Zone</th><th class="p-3">الإجمالي</th><th class="p-3">البوتات %</th><th class="p-3">التكلفة</th><th class="p-3">الحالة</th></tr>
                        </thead>
                        <tbody id="reports-table" class="divide-y divide-slate-700"></tbody>
                    </table>
                </div>
            </div>

            <!-- Tab: Costs -->
            <div id="tab-costs" class="hidden">
                <div class="bg-slate-800 p-4 rounded-xl border border-slate-700">
                    <h2 class="mb-4 text-sm md:text-base font-bold">أدخل تكلفة الـ Zone</h2>
                    <div class="flex gap-2">
                        <input type="text" id="cost-zone" placeholder="Zone ID" class="bg-slate-900 p-2 rounded text-white border border-slate-600 w-1/3">
                        <input type="number" id="cost-amount" placeholder="التكلفة بالدولار" class="bg-slate-900 p-2 rounded text-white border border-slate-600 w-1/3">
                        <button onclick="saveCost()" class="bg-blue-600 px-4 rounded font-bold w-1/3 text-sm">حفظ</button>
                    </div>
                    <button onclick="generateMock()" class="mt-6 w-full bg-purple-600 py-2 rounded font-bold text-sm">توليد بيانات وهمية للتجربة</button>
                </div>
            </div>

        </div>

        <script>
            let chart = null;
            const getVal = (id) => document.getElementById(id).value;

            function switchTab(tab) {
                ['live', 'reports', 'costs'].forEach(t => {
                    document.getElementById('tab-'+t).classList.add('hidden');
                    document.getElementById('tab-btn-'+t).className = "px-4 py-2 text-slate-400 font-bold whitespace-nowrap";
                });
                document.getElementById('tab-'+tab).classList.replace('hidden', 'block');
                document.getElementById('tab-btn-'+tab).className = "px-4 py-2 text-blue-500 border-b-2 border-blue-500 font-bold whitespace-nowrap";
            }

            async function applyFilters() { loadAll(); }
            function resetFilters() { 
                ['filter-start','filter-end','filter-device','filter-zone'].forEach(id => document.getElementById(id).value = '');
                loadAll(); 
            }

            async function saveCost() {
                const z = getVal('cost-zone'); const a = getVal('cost-amount');
                if(!z || !a) return alert("اكتب الـ Zone والتكلفة");
                await fetch('/api/cost', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({zone_id:z, amount:parseFloat(a)})});
                alert("تم الحفظ!"); loadAll();
            }

            async function generateMock() {
                await fetch('/api/mock-data', {method: 'POST'}); loadAll();
            }

            async function loadAll() {
                const params = new URLSearchParams({
                    zone: getVal('filter-zone'), device: getVal('filter-device'),
                    start_date: getVal('filter-start'), end_date: getVal('filter-end')
                });
                const res = await fetch('/api/stats?' + params);
                const data = await res.json();
                
                document.getElementById('kpi-total').innerText = data.total;
                document.getElementById('kpi-valid').innerText = data.valid;
                document.getElementById('kpi-invalid').innerText = data.invalid;
                document.getElementById('kpi-cost').innerText = '$' + data.total_cost;

                const tbody = document.getElementById('live-table');
                tbody.innerHTML = '';
                data.recent.forEach(v => {
                    const c = v.verdict === 'valid' ? 'text-green-500' : v.verdict === 'invalid' ? 'text-red-500' : 'text-yellow-500';
                    tbody.innerHTML += `<tr><td class="p-3 text-slate-400">${v.time}</td><td class="p-3">${v.zone}</td><td class="p-3">${v.device}</td><td class="p-3 ${c}">${v.verdict}</td></tr>`;
                });

                loadReports();
            }

            async function loadReports() {
                const res = await fetch('/api/reports/zones');
                const data = await res.json();
                const tbody = document.getElementById('reports-table');
                tbody.innerHTML = '';
                data.forEach(z => {
                    const rc = z.bot_rate > 30 ? 'bg-red-500/20 text-red-500' : z.bot_rate > 10 ? 'bg-yellow-500/20 text-yellow-500' : 'bg-green-500/20 text-green-500';
                    tbody.innerHTML += `<tr><td class="p-3 font-bold text-blue-400">${z.zone}</td><td class="p-3">${z.total}</td><td class="p-3"><span class="${rc} px-2 py-1 rounded">${z.bot_rate}%</span></td><td class="p-3">$${z.cost}</td><td class="p-3">${z.bot_rate > 30 ? '⚠️ خسارة' : '✅ آمن'}</td></tr>`;
                });
            }

            loadAll(); setInterval(loadAll, 15000);
        </script>
    </body>
    </html>
    """
