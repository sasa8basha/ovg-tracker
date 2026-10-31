from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
from pydantic import BaseModel
from datetime import datetime
from urllib.parse import urlparse, parse_qs

# إعداد الداتابيز (ملف صغير بيتعمل لوحده)
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    
    # كشف البوتس
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
    if score >= 70:
        verdict = "invalid"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "valid"
        
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
    if zone_id == "unknown":
         zone_id = query_params.get("zone", ["unknown"])[0]

    result = analyze_visit(payload.dict())
    
    visit = VisitModel(
        ip=client_ip,
        user_agent=payload.nav.get("ua"),
        zone_id=zone_id,
        score=result["score"],
        verdict=result["verdict"],
        evidence=result["evidence"],
        raw_data=payload.dict()
    )
    db.add(visit)
    db.commit()
    db.close()
    
    return {"status": "success", "verdict": result["verdict"], "score": result["score"]}