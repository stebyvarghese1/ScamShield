"""ScamShield Backend Application Entrypoint"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from backend.routers import analyze, scans, stats, education, settings

app = FastAPI(
    title="ScamShield API",
    description="Personal Cybersecurity Assistant for Phishing, Scam, and Quishing Detection",
    version="1.0.0"
)

# Enable CORS for flexible integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(analyze.router)
app.include_router(scans.router)
app.include_router(stats.router)
app.include_router(education.router)
app.include_router(settings.router)

@app.get("/api/health")
def health_check():
    return {"status": "online", "product": "ScamShield", "version": "1.0.0"}

# Mount frontend directory for seamless single-server deployment
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    def serve_frontend():
        index_path = os.path.join(FRONTEND_DIR, "index.html")
        return FileResponse(index_path)
