"""
app.py — PhishTrap FastAPI Backend (Phase 5)

Run from ~/phishtrap/:
    uvicorn app:app --host 0.0.0.0 --port 8080 --reload

Open in Firefox (inside Ubuntu VM):
    http://127.0.0.1:8080
"""

import asyncio
import glob
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, File, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Make sure the pipeline modules are importable from this same directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ─── In-memory state ──────────────────────────────────────────────────────────
_ws_queues: dict[str, asyncio.Queue] = {}
HISTORY_FILE = "history.json"
_history: list[dict] = []


def _load_history():
    global _history
    if os.path.exists(HISTORY_FILE):
        try:
            _history = json.load(open(HISTORY_FILE))
        except Exception:
            _history = []


def _save_history():
    try:
        json.dump(_history[-50:], open(HISTORY_FILE, "w"), indent=2)
    except Exception:
        pass


REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


def _save_full_report(run_id: str, report: dict, message_id: str = None):
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        report_copy = dict(report)
        report_copy["run_id"] = run_id
        if message_id:
            report_copy["message_id"] = message_id
        path = os.path.join(REPORTS_DIR, f"{run_id}.json")
        with open(path, "w") as f:
            json.dump(report_copy, f, indent=2)
        if message_id:
            msg_path = os.path.join(REPORTS_DIR, f"msg_{message_id}.json")
            with open(msg_path, "w") as f:
                json.dump(report_copy, f, indent=2)
    except Exception as e:
        print(f"[app] Error saving full report: {e}")


def _add_to_history(run_id: str, report: dict, filename: str, message_id: str = None):
    _save_full_report(run_id, report, message_id=message_id)
    entry = {
        "run_id":         run_id,
        "timestamp":      time.strftime("%Y-%m-%d %H:%M:%S"),
        "filename":       filename,
        "verdict":        report.get("verdict"),
        "combined_score": report.get("combined_score"),
        "sender":         report.get("sender"),
        "subject":        report.get("subject"),
        "vector_verdicts":report.get("vector_verdicts"),
    }
    if message_id:
        entry["message_id"] = message_id
        entry["source"] = "gmail"
    _history.append(entry)
    _save_history()


# ─── App lifespan ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    _load_history()
    os.makedirs("demo_artifacts", exist_ok=True)
    os.makedirs("uploads", exist_ok=True)
    yield


app = FastAPI(title="PhishTrap", lifespan=lifespan)


# ─── Pipeline runner ──────────────────────────────────────────────────────────
async def _run_pipeline_async(run_id: str, eml_path: str, filename: str):
    queue = _ws_queues.get(run_id)

    def on_stage(stage: str, status: str, detail: str = ""):
        if queue:
            try:
                queue.put_nowait({
                    "type": "stage",
                    "stage": stage,
                    "status": status,
                    "detail": detail,
                })
            except asyncio.QueueFull:
                pass

    loop = asyncio.get_event_loop()

    def _run():
        from run_pipeline import run_pipeline
        return run_pipeline(eml_path, on_stage=on_stage)

    try:
        report = await loop.run_in_executor(None, _run)
        _add_to_history(run_id, report, filename)
        if queue:
            queue.put_nowait({"type": "done", "run_id": run_id, "report": report})
    except Exception as e:
        if queue:
            queue.put_nowait({"type": "error", "message": str(e)})


def _start_run(eml_path: str, filename: str) -> str:
    run_id = str(uuid.uuid4())[:8]
    _ws_queues[run_id] = asyncio.Queue(maxsize=200)
    asyncio.create_task(_run_pipeline_async(run_id, eml_path, filename))
    return run_id


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.post("/upload-email")
async def upload_email(file: UploadFile = File(...)):
    save_path = f"uploads/{uuid.uuid4().hex}_{file.filename}"
    with open(save_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    run_id = _start_run(save_path, file.filename)
    return {"run_id": run_id}


@app.get("/preset/malicious")
async def preset_malicious():
    files = sorted(glob.glob("demo_artifacts/lure_combined*.eml"))
    if not files:
        return JSONResponse(
            {"error": "No combined lure found. Run: python3 generate_lure.py"},
            status_code=404,
        )
    path = files[-1]
    run_id = _start_run(path, os.path.basename(path))
    return {"run_id": run_id, "file": os.path.basename(path)}


@app.get("/preset/benign")
async def preset_benign():
    files = sorted(glob.glob("demo_artifacts/benign*.eml"))
    if not files:
        return JSONResponse(
            {"error": "No benign email found. Run: python3 generate_benign.py"},
            status_code=404,
        )
    path = files[-1]
    run_id = _start_run(path, os.path.basename(path))
    return {"run_id": run_id, "file": os.path.basename(path)}


@app.get("/generate/lure")
async def generate_lure(vector: Optional[str] = None):
    flag_map = {
        "image": "--image-only",
        "link":  "--link-only",
        "pdf":   "--pdf-only",
        "text":  "--text-only",
    }
    flag = flag_map.get(vector or "", "")
    cmd  = [sys.executable, "generate_lure.py"] + ([flag] if flag else [])
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, cwd=os.getcwd()
        )
        lines = [l for l in result.stdout.strip().split("\n") if l.startswith("Generated:")]
        if not lines:
            return JSONResponse(
                {"error": "Generation failed", "detail": result.stderr}, status_code=500
            )
        path   = lines[0].replace("Generated: ", "").strip()
        run_id = _start_run(path, os.path.basename(path))
        return {"run_id": run_id, "file": os.path.basename(path)}
    except subprocess.TimeoutExpired:
        return JSONResponse({"error": "Generation timed out"}, status_code=500)


@app.get("/generate/benign")
async def generate_benign_ep():
    try:
        result = subprocess.run(
            [sys.executable, "generate_benign.py"],
            capture_output=True, text=True, timeout=15, cwd=os.getcwd(),
        )
        lines = [l for l in result.stdout.strip().split("\n") if l.startswith("Generated:")]
        if not lines:
            return JSONResponse({"error": "Generation failed"}, status_code=500)
        path   = lines[0].replace("Generated: ", "").strip()
        run_id = _start_run(path, os.path.basename(path))
        return {"run_id": run_id, "file": os.path.basename(path)}
    except subprocess.TimeoutExpired:
        return JSONResponse({"error": "Generation timed out"}, status_code=500)


@app.get("/history")
async def history():
    _load_history()
    return {"runs": list(reversed(_history))[:50]}


@app.get("/api/report/{run_id}")
async def get_report(run_id: str):
    path = os.path.join(REPORTS_DIR, f"{run_id}.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    # Check if run_id is a message ID
    msg_path = os.path.join(REPORTS_DIR, f"msg_{run_id}.json")
    if os.path.exists(msg_path):
        with open(msg_path) as f:
            return json.load(f)
    # Fallback to history summary if full report not saved
    _load_history()
    for h in _history:
        if h.get("run_id") == run_id or h.get("message_id") == run_id:
            return h
    return JSONResponse({"error": "Report not found", "run_id": run_id}, status_code=404)


@app.get("/api/gmail-feed")
async def gmail_feed():
    _load_history()
    gmail_runs = [r for r in reversed(_history) if r.get("source") == "gmail" or r.get("message_id")]
    return {"gmail_runs": gmail_runs[:50]}


@app.websocket("/ws/{run_id}")
async def ws_pipeline(websocket: WebSocket, run_id: str):
    await websocket.accept()
    if run_id not in _ws_queues:
        await websocket.send_json({"type": "error", "message": f"Unknown run: {run_id}"})
        await websocket.close()
        return
    queue = _ws_queues[run_id]
    try:
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=120)
                await websocket.send_json(msg)
                if msg.get("type") in ("done", "error"):
                    break
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "heartbeat"})
    except WebSocketDisconnect:
        pass
    finally:
        _ws_queues.pop(run_id, None)


@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    html_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(html_path) as f:
        return f.read()


app.mount("/static", StaticFiles(directory="static"), name="static")
