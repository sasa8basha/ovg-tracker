from fastapi import FastAPI, Request, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import random
import string

DATABASE_URL = "sqlite:///./ovg.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

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

Base.metadata.create_all(bind=engine)

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class TrackPayload(BaseModel):
    url: str
    nav: dict
    fingerprint: dict
    behavior: dict

def analyze_visit(data: dict):
    score = 0
    evidence = []
    nav = data.get("nav", {})
    fp = data.get("fingerprint", {})
    behavior = data.get("behavior", {})
    
    if nav.get("webdriver") is True:
        score += 80
        evidence.append("WebDriver detected")
    ua = nav.get("ua", "").lower()
    if not ua or "headless" in ua or "python" in ua:
        score += 90
        evidence.append("Suspicious User-Agent")
    tom = behavior.get("time_on_page_ms", 0)
    if tom < 1500:
        score += 40
        evidence.append(f"Time too short: {tom}ms")
    if behavior.get("events", {}).get("mousemove", 0) == 0 and nav.get("touch") is False:
        score += 30
        evidence.append("No mouse movement")
    renderer = str(fp.get("webgl", {}).get("renderer", "")).lower()
    if "swiftshader" in renderer or "llvmpipe" in renderer:
        score += 50
        evidence.append("Software Renderer")

    score = min(100, score)
    if score >= 70: verdict = "invalid"
    elif score >= 30: verdict = "suspicious"
    else: verdict = "valid"
    return {"score": score, "verdict": verdict, "evidence": evidence}

@app.get("/")
def read_root():
    return {"status": "OVG Server is running!"}

@app.post("/api/track")
async def track_visit(payload: TrackPayload, request: Request):
    db = SessionLocal()
    client_ip = request.client.host
    parsed_url = urlparse(payload.url)
    query_params = parse_qs(parsed_url.query)
    zone_id = query_params.get("zoneid", ["unknown"])[0]
    
    result = analyze_visit(payload.dict())
    
    visit = VisitModel(
        ip=client_ip, user_agent=payload.nav.get("ua"), zone_id=zone_id,
        score=result["score"], verdict=result["verdict"], evidence=result["evidence"], raw_data=payload.dict()
    )
    db.add(visit)
    db.commit()
    db.close()
    return {"status": "success"}

# API للإحصائيات العامة
@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(VisitModel).count()
    valid = db.query(VisitModel).filter(VisitModel.verdict == "valid").count()
    invalid = db.query(VisitModel).filter(VisitModel.verdict == "invalid").count()
    suspicious = db.query(VisitModel).filter(VisitModel.verdict == "suspicious").count()
    
    visits = db.query(VisitModel).order_by(VisitModel.id.desc()).limit(50).all()
    recent_visits = [{"time": v.timestamp.strftime("%H:%M:%S"), "zone": v.zone_id, "score": v.score, "verdict": v.verdict, "evidence": ", ".join(v.evidence) if v.evidence else "طبيعي"} for v in visits]
    return {"total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious, "recent": recent_visits}

# API تقارير الـ Zones
@app.get("/api/reports/zones")
def get_zone_reports(db: Session = Depends(get_db)):
    # تجميع البيانات حسب الـ Zone
    zones = db.query(
        VisitModel.zone_id,
        func.count(VisitModel.id).label('total'),
        func.sum(func.iif(VisitModel.verdict == 'valid', 1, 0)).label('valid'),
        func.sum(func.iif(VisitModel.verdict == 'invalid', 1, 0)).label('invalid')
    ).group_by(VisitModel.zone_id).all()
    
    report = []
    for z in zones:
        total = z.total
        valid = z.valid or 0
        invalid = z.invalid or 0
        bot_rate = round((invalid / total) * 100, 1) if total > 0 else 0
        report.append({
            "zone": z.zone_id,
            "total": total,
            "valid": valid,
            "invalid": invalid,
            "bot_rate": bot_rate
        })
    # ترتيب من الأسوأ للأفضل (حسب نسبة البوت)
    report.sort(key=lambda x: x['bot_rate'], reverse=True)
    return report

# زرار لتوليد بيانات وهمية للتجربة
@app.post("/api/mock-data")
def generate_mock(db: Session = Depends(get_db)):
    zones = ["10245", "88321", "55410", "99120", "33215"]
    for _ in range(200): # 200 زيارة وهمية
        z = random.choice(zones)
        verdict = random.choices(["valid", "invalid", "suspicious"], weights=[70, 20, 10])[0]
        score = random.randint(0, 30) if verdict == "valid" else (random.randint(70, 100) if verdict == "invalid" else random.randint(30, 69))
        evidence = ["طبيعي"] if verdict == "valid" else ["WebDriver detected"] if verdict == "invalid" else ["Time too short"]
        
        v = VisitModel(ip="127.0.0.1", user_agent="Mozilla/5.0", zone_id=z, score=score, verdict=verdict, evidence=evidence, raw_data={})
        db.add(v)
    db.commit()
    return {"status": "Mock data generated"}

# صفحة الداشبورد الاحترافية (النسخة الجديدة بالتابات)
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
    <!DOCTYPE html>
    <html lang="ar" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OVG Pro Reports</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
        <style>body { font-family: 'Cairo', sans-serif; background-color: #0f172a; color: #f8fafc; }</style>
    </head>
    <body class="p-4 md:p-8">
        <div class="max-w-7xl mx-auto">
            <header class="mb-6 flex justify-between items-center border-b border-slate-700 pb-4">
                <h1 class="text-2xl md:text-3xl font-bold text-blue-500">OVG Pro <span class="text-slate-400 text-sm md:text-lg">(Reports)</span></h1>
                <div class="flex gap-2">
                    <button onclick="generateMock()" class="bg-purple-600 hover:bg-purple-700 text-white px-3 py-1.5 rounded-lg text-xs md:text-sm font-semibold transition">توليد بيانات وهمية</button>
                    <button onclick="loadAll()" class="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1.5 rounded-lg text-xs md:text-sm font-semibold transition">تحديث</button>
                </div>
            </header>

            <!-- Tabs -->
            <div class="flex border-b border-slate-700 mb-6 space-x-1 space-x-reverse">
                <button id="tab-btn-live" onclick="switchTab('live')" class="px-4 py-2 text-blue-500 border-b-2 border-blue-500 font-bold">آخر الزيارات (Live)</button>
                <button id="tab-btn-reports" onclick="switchTab('reports')" class="px-4 py-2 text-slate-400 hover:text-white font-bold">تقارير الـ Zones</button>
            </div>

            <!-- KPI Cards -->
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3 md:gap-4 mb-6">
                <div class="bg-slate-800 p-4 md:p-6 rounded-xl border border-slate-700 shadow-lg">
                    <p class="text-slate-400 text-xs md:text-sm mb-1">إجمالي الزيارات</p>
                    <p id="kpi-total" class="text-2xl md:text-3xl font-bold text-white">0</p>
                </div>
                <div class="bg-slate-800 p-4 md:p-6 rounded-xl border border-slate-700 shadow-lg border-t-4 border-t-green-500">
                    <p class="text-slate-400 text-xs md:text-sm mb-1">صالحة (Valid)</p>
                    <p id="kpi-valid" class="text-2xl md:text-3xl font-bold text-green-500">0</p>
                </div>
                <div class="bg-slate-800 p-4 md:p-6 rounded-xl border border-slate-700 shadow-lg border-t-4 border-t-yellow-500">
                    <p class="text-slate-400 text-xs md:text-sm mb-1">مشبوهة (Suspicious)</p>
                    <p id="kpi-suspicious" class="text-2xl md:text-3xl font-bold text-yellow-500">0</p>
                </div>
                <div class="bg-slate-800 p-4 md:p-6 rounded-xl border border-slate-700 shadow-lg border-t-4 border-t-red-500">
                    <p class="text-slate-400 text-xs md:text-sm mb-1">بوتات (Invalid)</p>
                    <p id="kpi-invalid" class="text-2xl md:text-3xl font-bold text-red-500">0</p>
                </div>
            </div>

            <!-- Tab: Live Traffic -->
            <div id="tab-live" class="block">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div class="bg-slate-800 p-4 md:p-6 rounded-xl border border-slate-700 shadow-lg col-span-1">
                        <h2 class="text-md md:text-lg font-bold mb-4 text-slate-300">نسبة الترافيك</h2>
                        <div class="relative h-48 md:h-64 flex justify-center">
                            <canvas id="verdictChart"></canvas>
                        </div>
                    </div>
                    <div class="bg-slate-800 rounded-xl border border-slate-700 shadow-lg col-span-1 md:col-span-2 overflow-hidden">
                        <div class="p-4 border-b border-slate-700"><h2 class="text-md md:text-lg font-bold text-slate-300">آخر الزيارات</h2></div>
                        <div class="overflow-x-auto">
                            <table class="w-full text-xs md:text-sm text-right">
                                <thead class="text-slate-400 bg-slate-900/50">
                                    <tr>
                                        <th class="px-3 py-2">الوقت</th><th class="px-3 py-2">Zone</th><th class="px-3 py-2">الحكم</th><th class="px-3 py-2">السبب</th>
                                    </tr>
                                </thead>
                                <tbody id="visits-table" class="divide-y divide-slate-700"></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tab: Reports -->
            <div id="tab-reports" class="hidden">
                <div class="bg-slate-800 rounded-xl border border-slate-700 shadow-lg overflow-hidden">
                    <div class="p-4 border-b border-slate-700 bg-slate-900/50">
                        <h2 class="text-md md:text-lg font-bold text-slate-300">تقرير مجمع لكل Zone (مرتب من الأسوأ للأفضل)</h2>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="w-full text-xs md:text-sm text-right">
                            <thead class="text-slate-400 bg-slate-900">
                                <tr>
                                    <th class="px-4 py-3">Zone ID</th>
                                    <th class="px-4 py-3">إجمالي الزيارات</th>
                                    <th class="px-4 py-3">صالحة</th>
                                    <th class="px-4 py-3">بوتات</th>
                                    <th class="px-4 py-3">نسبة البوتات %</th>
                                </tr>
                            </thead>
                            <tbody id="zones-table" class="divide-y divide-slate-700"></tbody>
                        </table>
                    </div>
                </div>
            </div>

        </div>

        <script>
            let chartInstance = null;

            function switchTab(tab) {
                document.getElementById('tab-live').classList.replace('block', 'hidden');
                document.getElementById('tab-reports').classList.replace('block', 'hidden');
                document.getElementById('tab-live').classList.add('hidden');
                document.getElementById('tab-reports').classList.add('hidden');
                
                document.getElementById('tab-btn-live').className = "px-4 py-2 text-slate-400 hover:text-white font-bold";
                document.getElementById('tab-btn-reports').className = "px-4 py-2 text-slate-400 hover:text-white font-bold";

                document.getElementById('tab-' + tab).classList.replace('hidden', 'block');
                document.getElementById('tab-btn-' + tab).className = "px-4 py-2 text-blue-500 border-b-2 border-blue-500 font-bold";
            }

            async function loadAll() {
                loadStats();
                loadZoneReports();
            }

            async function generateMock() {
                await fetch('/api/mock-data', {method: 'POST'});
                loadAll();
            }

            async function loadStats() {
                try {
                    const res = await fetch('/api/stats');
                    const data = await res.json();

                    document.getElementById('kpi-total').innerText = data.total;
                    document.getElementById('kpi-valid').innerText = data.valid;
                    document.getElementById('kpi-suspicious').innerText = data.suspicious;
                    document.getElementById('kpi-invalid').innerText = data.invalid;

                    const tbody = document.getElementById('visits-table');
                    tbody.innerHTML = '';
                    data.recent.forEach(v => {
                        const color = v.verdict === 'valid' ? 'text-green-500 bg-green-500/10' : v.verdict === 'invalid' ? 'text-red-500 bg-red-500/10' : 'text-yellow-500 bg-yellow-500/10';
                        tbody.innerHTML += `<tr class="hover:bg-slate-700/50"><td class="px-3 py-2 text-slate-400">${v.time}</td><td class="px-3 py-2 font-semibold">${v.zone}</td><td class="px-3 py-2"><span class="${color} px-2 py-1 rounded text-xs font-bold">${v.verdict}</span></td><td class="px-3 py-2 text-slate-400 text-xs">${v.evidence}</td></tr>`;
                    });

                    if (chartInstance) chartInstance.destroy();
                    const ctx = document.getElementById('verdictChart').getContext('2d');
                    chartInstance = new Chart(ctx, {
                        type: 'doughnut',
                        data: { labels: ['Valid', 'Suspicious', 'Invalid'], datasets: [{ data: [data.valid, data.suspicious, data.invalid], backgroundColor: ['#22c55e', '#eab308', '#ef4444'], borderWidth: 0 }] },
                        options: { cutout: '70%', plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', font: {size: 10} } } } }
                    });
                } catch (e) { console.error(e); }
            }

            async function loadZoneReports() {
                try {
                    const res = await fetch('/api/reports/zones');
                    const data = await res.json();

                    const tbody = document.getElementById('zones-table');
                    tbody.innerHTML = '';
                    data.forEach(z => {
                        const rateColor = z.bot_rate > 30 ? 'text-red-500 font-bold' : z.bot_rate > 10 ? 'text-yellow-500' : 'text-green-500';
                        tbody.innerHTML += `
                            <tr class="hover:bg-slate-700/50">
                                <td class="px-4 py-3 font-semibold text-blue-400">${z.zone}</td>
                                <td class="px-4 py-3 font-bold text-white">${z.total}</td>
                                <td class="px-4 py-3 text-green-500">${z.valid}</td>
                                <td class="px-4 py-3 text-red-500">${z.invalid}</td>
                                <td class="px-4 py-3"><span class="${rateColor} bg-slate-900 px-2 py-1 rounded">${z.bot_rate}%</span></td>
                            </tr>
                        `;
                    });
                } catch (e) { console.error(e); }
            }

            loadAll();
            setInterval(loadStats, 10000); // Live updates for stats
        </script>
    </body>
    </html>
    """
