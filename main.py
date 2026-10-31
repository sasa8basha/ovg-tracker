from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import json

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

# API للإحصائيات
@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(VisitModel).count()
    valid = db.query(VisitModel).filter(VisitModel.verdict == "valid").count()
    invalid = db.query(VisitModel).filter(VisitModel.verdict == "invalid").count()
    suspicious = db.query(VisitModel).filter(VisitModel.verdict == "suspicious").count()
    
    visits = db.query(VisitModel).order_by(VisitModel.id.desc()).limit(50).all()
    recent_visits = []
    for v in visits:
        recent_visits.append({
            "time": v.timestamp.strftime("%H:%M:%S"),
            "zone": v.zone_id,
            "score": v.score,
            "verdict": v.verdict,
            "evidence": ", ".join(v.evidence) if v.evidence else "طبيعي"
        })
        
    return {"total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious, "recent": recent_visits}

# صفحة الداشبورد الاحترافية
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    html_content = """
    <!DOCTYPE html>
    <html lang="ar" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OVG Pro Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
        <style>body { font-family: 'Cairo', sans-serif; background-color: #0f172a; color: #f8fafc; }</style>
    </head>
    <body class="p-4 md:p-8">
        <div class="max-w-7xl mx-auto">
            <header class="mb-8 flex justify-between items-center border-b border-slate-700 pb-4">
                <h1 class="text-3xl font-bold text-blue-500">OVG Pro <span class="text-slate-400 text-lg">(Live)</span></h1>
                <button onclick="loadData()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-semibold transition">تحديث البيانات</button>
            </header>

            <!-- KPI Cards -->
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg">
                    <p class="text-slate-400 text-sm mb-1">إجمالي الزيارات</p>
                    <p id="kpi-total" class="text-3xl font-bold text-white">0</p>
                </div>
                <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg border-t-4 border-t-green-500">
                    <p class="text-slate-400 text-sm mb-1">زيارات صالحة (Valid)</p>
                    <p id="kpi-valid" class="text-3xl font-bold text-green-500">0</p>
                </div>
                <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg border-t-4 border-t-yellow-500">
                    <p class="text-slate-400 text-sm mb-1">مشبوهة (Suspicious)</p>
                    <p id="kpi-suspicious" class="text-3xl font-bold text-yellow-500">0</p>
                </div>
                <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg border-t-4 border-t-red-500">
                    <p class="text-slate-400 text-sm mb-1">بوتات (Invalid)</p>
                    <p id="kpi-invalid" class="text-3xl font-bold text-red-500">0</p>
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-8 mb-8">
                <!-- Chart -->
                <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg col-span-1">
                    <h2 class="text-lg font-bold mb-4 text-slate-300">نسبة الترافيك</h2>
                    <div class="relative h-64 flex justify-center">
                        <canvas id="verdictChart"></canvas>
                    </div>
                </div>

                <!-- Table -->
                <div class="bg-slate-800 rounded-xl border border-slate-700 shadow-lg col-span-1 md:col-span-2 overflow-hidden">
                    <div class="p-6 border-b border-slate-700 flex justify-between items-center">
                        <h2 class="text-lg font-bold text-slate-300">آخر الزيارات</h2>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="w-full text-sm text-right">
                            <thead class="text-xs text-slate-400 uppercase bg-slate-900/50">
                                <tr>
                                    <th class="px-6 py-3">الوقت</th>
                                    <th class="px-6 py-3">Zone</th>
                                    <th class="px-6 py-3">السكور</th>
                                    <th class="px-6 py-3">الحكم</th>
                                    <th class="px-6 py-3">السبب</th>
                                </tr>
                            </thead>
                            <tbody id="visits-table" class="divide-y divide-slate-700">
                                <!-- Rows injected by JS -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <script>
            let chartInstance = null;

            async function loadData() {
                try {
                    const res = await fetch('/api/stats');
                    const data = await res.json();

                    // Update KPIs
                    document.getElementById('kpi-total').innerText = data.total;
                    document.getElementById('kpi-valid').innerText = data.valid;
                    document.getElementById('kpi-suspicious').innerText = data.suspicious;
                    document.getElementById('kpi-invalid').innerText = data.invalid;

                    // Update Table
                    const tbody = document.getElementById('visits-table');
                    tbody.innerHTML = '';
                    data.recent.forEach(v => {
                        const color = v.verdict === 'valid' ? 'text-green-500 bg-green-500/10' : 
                                      v.verdict === 'invalid' ? 'text-red-500 bg-red-500/10' : 'text-yellow-500 bg-yellow-500/10';
                        tbody.innerHTML += `
                            <tr class="hover:bg-slate-700/50 transition">
                                <td class="px-6 py-4 text-slate-400">${v.time}</td>
                                <td class="px-6 py-4 font-semibold">${v.zone}</td>
                                <td class="px-6 py-4">${v.score}</td>
                                <td class="px-6 py-4"><span class="${color} px-2 py-1 rounded text-xs font-bold">${v.verdict.toUpperCase()}</span></td>
                                <td class="px-6 py-4 text-slate-400 text-xs">${v.evidence}</td>
                            </tr>
                        `;
                    });

                    // Update Chart
                    if (chartInstance) chartInstance.destroy();
                    const ctx = document.getElementById('verdictChart').getContext('2d');
                    chartInstance = new Chart(ctx, {
                        type: 'doughnut',
                        data: {
                            labels: ['Valid', 'Suspicious', 'Invalid'],
                            datasets: [{
                                data: [data.valid, data.suspicious, data.invalid],
                                backgroundColor: ['#22c55e', '#eab308', '#ef4444'],
                                borderWidth: 0
                            }]
                        },
                        options: { cutout: '75%', plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } } }
                    });

                } catch (e) {
                    console.error("Error loading data", e);
                }
            }

            // Load on start and every 10 seconds
            loadData();
            setInterval(loadData, 10000);
        </script>
    </body>
    </html>
    """
    return html_content
