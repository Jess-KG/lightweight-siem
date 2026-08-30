from fastapi import FastAPI
from pathlib import Path
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from src.siem.test_loader import load_test_events
from src.siem.normalizer.normalizer import normalize
from src.siem.detection.detection_v2 import detect_alerts

app = FastAPI(title = "Lightweight SIEM Dashboard")
FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"
app.mount("/static", 
          StaticFiles(directory=FRONTEND_DIR),
          name="static")

@app.get('/')
def root():
    return {"message": "SIEM API is running"}

@app.get('/dashboard')
def get_dashboard():
    return FileResponse(FRONTEND_DIR / "index.html")

@app.get("/events")
def events_page():
    return FileResponse(FRONTEND_DIR / "events.html")

@app.get("/alerts")
def events_page():
    return FileResponse(FRONTEND_DIR / "alerts.html")

@app.get("/api/events")
def get_events():
    print("STARTED EVENTS")
    raw_events = list(
        load_test_events(
            "C:\\Users\\grewa\\Documents\\GitHub\\lightweight-siem\\Simulation_2\\file3.xml"
        )
    )

    normalized_events = []

    for e in raw_events:
        normalized_event = normalize(e)

        if normalized_event:
            normalized_events.append(normalized_event)

    return {
        "events": normalized_events,
        "total": len(normalized_events)
    }

@app.get("/api/alerts")
def get_alerts():
    raw_events = list(load_test_events("C:\\Users\\grewa\\Documents\\GitHub\\lightweight-siem\\Simulation_2\\file3.xml"))

    normalized_events = []

    for e in raw_events:
        normalized_event = normalize(e)

        if normalized_event:
            normalized_events.append(normalized_event)

    alerts = detect_alerts(normalized_events)

    return {
        "alerts": alerts,
        "total": len(alerts)
    }