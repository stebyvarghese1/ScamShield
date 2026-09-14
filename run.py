"""ScamShield One-Click Startup Runner"""
import os
import sys
import webbrowser
import threading
import time
import uvicorn

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 8000))

def open_browser():
    time.sleep(1.2)
    url = f"http://{HOST}:{PORT}"
    print(f"\n[+] Opening ScamShield in browser: {url}")
    try:
        webbrowser.open(url)
    except Exception:
        pass

def main():
    print("=" * 60)
    print("  [SHIELD] SCAMSHIELD - Personal Cybersecurity Assistant")
    print("  Understand Before You Trust")
    print("=" * 60)
    print("[+] Starting FastAPI Security Backend...")
    print(f"[+] Dashboard URL: http://{HOST}:{PORT}")
    print(f"[+] API Documentation: http://{HOST}:{PORT}/docs")
    print("=" * 60)

    # Launch browser automatically in separate daemon thread
    threading.Thread(target=open_browser, daemon=True).start()

    # Start Uvicorn Server with live reload
    uvicorn.run(
        "backend.main:app",
        host=HOST,
        port=PORT,
        reload=True,
        log_level="info"
    )

if __name__ == "__main__":
    main()
