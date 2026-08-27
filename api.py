"""
APKGuard - Module 4: FastAPI Backend
REST API that ties together Modules 1, 2, and 3 into a single pipeline.
The React dashboard calls these endpoints.
"""

import json
import os
import re
import shutil
import sys
import asyncio
import uuid
from pathlib import Path
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ── Add APKGuard root to path so we can import our modules ────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent))

from decompiler import analyse_apk
from classifier import load_model, score_apk
from llm_explainer import explain_apk

# ── Configuration ─────────────────────────────────────────────────────────────
BASE_DIR    = Path(os.getenv("APKGUARD_HOME", Path(__file__).resolve().parent))
UPLOADS_DIR = BASE_DIR / "uploads"
OUTPUT_DIR  = BASE_DIR / "output"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
# ── Path safety ───────────────────────────────────────────────────────────────
# apk_name arrives from the URL and from upload filenames, both attacker
# controlled. Without this, DELETE /report/.. resolves to BASE_DIR and
# shutil.rmtree deletes the entire application.
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


def safe_output_dir(apk_name: str) -> Path:
    """Resolve an APK name to a directory strictly inside OUTPUT_DIR."""
    if apk_name in (".", "..") or not SAFE_NAME.match(apk_name):
        raise HTTPException(status_code=400, detail="Invalid APK name")
    target = (OUTPUT_DIR / apk_name).resolve()
    if not target.is_relative_to(OUTPUT_DIR.resolve()):
        raise HTTPException(status_code=400, detail="Invalid APK name")
    return target

# ── In-memory job store (resets on restart — fine for demo) ──────────────────
# job_id → { status, progress, result, error }
jobs: dict[str, dict] = {}

# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="APKGuard API",
    description="GenAI-Powered Banking APK Threat Intelligence Platform",
    version="1.0.0",
)

# Allow React dev server to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Helper ────────────────────────────────────────────────────────────────────

def job_update(job_id: str, status: str, progress: int, message: str):
    jobs[job_id]["status"]   = status
    jobs[job_id]["progress"] = progress
    jobs[job_id]["message"]  = message
    jobs[job_id]["updated_at"] = datetime.now().isoformat()
    print(f"[{job_id[:8]}] [{progress}%] {message}")


# ── Background analysis pipeline ─────────────────────────────────────────────

async def run_pipeline(job_id: str, apk_path: Path, apk_name: str, run_llm: bool):
    """
    Full APKGuard pipeline runs in background so the API stays responsive.
    """
    try:
        # ── Step 1: Decompile ─────────────────────────────────────
        job_update(job_id, "running", 10, "Decompiling APK with APKTool + JADX...")
        await asyncio.sleep(0.1)  # yield to event loop

        loop = asyncio.get_event_loop()
        report = await loop.run_in_executor(None, analyse_apk, str(apk_path))

        job_update(job_id, "running", 40, "Decompilation complete. Running ML classifier...")

        # ── Step 2: ML Score ──────────────────────────────────────
        await asyncio.sleep(0.1)
        final_score, category = await loop.run_in_executor(None, score_apk, apk_name)

        job_update(job_id, "running", 65, f"ML Score: {final_score}/100 ({category}). Running LLM analysis...")

        # ── Step 3: LLM Explanation (optional — takes ~2 min) ─────
        if run_llm:
            await asyncio.sleep(0.1)
            llm_result = await loop.run_in_executor(None, explain_apk, apk_name)
            job_update(job_id, "running", 90, "LLM analysis complete. Building report...")
        else:
            job_update(job_id, "running", 90, "Skipping LLM (fast mode). Building report...")

        # ── Load final report ─────────────────────────────────────
        report_path = OUTPUT_DIR / apk_name / "report.json"
        with open(report_path, "r", encoding="utf-8") as f:
            final_report = json.load(f)

        jobs[job_id]["status"]   = "done"
        jobs[job_id]["progress"] = 100
        jobs[job_id]["message"]  = "Analysis complete"
        jobs[job_id]["result"]   = final_report
        jobs[job_id]["updated_at"] = datetime.now().isoformat()

    except Exception as e:
        jobs[job_id]["status"]  = "error"
        jobs[job_id]["error"]   = str(e)
        jobs[job_id]["message"] = f"Pipeline failed: {e}"
        jobs[job_id]["updated_at"] = datetime.now().isoformat()
        print(f"[ERROR] Pipeline failed for {job_id}: {e}")
        import traceback; traceback.print_exc()


# ══════════════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/")
def root():
    return {
        "name":    "APKGuard API",
        "version": "1.0.0",
        "status":  "running",
        "docs":    "http://localhost:8000/docs",
    }


@app.get("/health")
def health():
    """Health check — also verifies ML model is loaded."""
    try:
        load_model()
        model_ok = True
    except Exception:
        model_ok = False

    return {
        "api":      "ok",
        "model":    "loaded" if model_ok else "not found — run: python classifier.py train",
        "timestamp": datetime.now().isoformat(),
    }


# ── Upload & Analyse ──────────────────────────────────────────────────────────

@app.post("/analyse")
async def analyse(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    run_llm: bool = True,
):
    """
    Upload an APK file and start the full analysis pipeline.
    Returns a job_id to poll for results.
    """
    MAX_BYTES = 100 * 1024 * 1024

    # Never trust the client's filename — it is an attacker-controlled header.
    # Path.name strips any directory component before we look at it.
    original_name = Path(file.filename or "").name
    if Path(original_name).suffix.lower() != ".apk":
        raise HTTPException(status_code=400, detail="Only .apk files are accepted")

    # Use the client's stem only if it is safe; otherwise generate our own.
    stem = Path(original_name).stem
    apk_name = stem if SAFE_NAME.match(stem) else uuid.uuid4().hex
    apk_path = UPLOADS_DIR / f"{apk_name}.apk"

    # Stream to disk and abort the moment the cap is exceeded. Reading the whole
    # body into memory first meant a 4GB upload exhausted RAM before the old
    # size check ever ran.
    try:
        written = 0
        with open(apk_path, "wb") as f:
            while chunk := await file.read(1024 * 1024):
                written += len(chunk)
                if written > MAX_BYTES:
                    raise HTTPException(status_code=400,
                                        detail="File too large (max 100MB)")
                f.write(chunk)

        # An APK is a ZIP. Validate the content, not just the extension.
        with open(apk_path, "rb") as f:
            if f.read(4) != b"PK\x03\x04":
                raise HTTPException(status_code=400,
                                    detail="Not a valid APK (bad ZIP header)")
    except HTTPException:
        apk_path.unlink(missing_ok=True)
        raise

    # Create job. UUID rather than name+timestamp: two uploads of the same
    # filename in the same second used to collide and overwrite each other.
    job_id = uuid.uuid4().hex[:12]
    jobs[job_id] = {
        "job_id":     job_id,
        "apk_name":      apk_name,
        "original_name": original_name,
        "status":     "queued",
        "progress":   0,
        "message":    "Queued for analysis",
        "result":     None,
        "error":      None,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
    }

    # Start background pipeline
    background_tasks.add_task(run_pipeline, job_id, apk_path, apk_name, run_llm)

    return {
        "job_id":  job_id,
        "message": "Analysis started",
        "poll_url": f"/job/{job_id}",
    }


# ── Job status polling ────────────────────────────────────────────────────────

@app.get("/job/{job_id}")
def get_job(job_id: str):
    """Poll this endpoint to get analysis progress and results."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs[job_id]


@app.get("/jobs")
def list_jobs():
    """List all jobs (most recent first)."""
    return sorted(jobs.values(), key=lambda j: j["created_at"], reverse=True)


# ── Report retrieval ──────────────────────────────────────────────────────────

@app.get("/report/{apk_name}")
def get_report(apk_name: str):
    """Get the full report for a previously analysed APK."""
    report_path = safe_output_dir(apk_name) / "report.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail=f"No report found for {apk_name}")
    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)


@app.get("/reports")
def list_reports():
    """List all analysed APKs with their summary scores."""
    reports = []
    for folder in OUTPUT_DIR.iterdir():
        report_path = folder / "report.json"
        if report_path.exists():
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    r = json.load(f)
                ml = r.get("ml_scoring", {})
                h  = r.get("heuristic_scoring", {})
                reports.append({
                    "apk_name":    r.get("apk_name", folder.name),
                    "package":     r.get("manifest", {}).get("package", "unknown"),
                    "final_score": ml.get("final_score", h.get("heuristic_score", 0)),
                    "category":    ml.get("category", h.get("category", "UNKNOWN")),
                    "analysed_at": r.get("analysed_at", ""),
                    "has_llm":     "llm_analysis" in r,
                })
            except Exception:
                pass
    return sorted(reports, key=lambda r: r["analysed_at"], reverse=True)


# ── Quick score (no LLM) ──────────────────────────────────────────────────────

@app.post("/quick-score")
async def quick_score(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    """Same as /analyse but skips LLM for faster results (~90 seconds)."""
    return await analyse(background_tasks, file, run_llm=False)


# ── Stats ─────────────────────────────────────────────────────────────────────

@app.get("/stats")
def stats():
    """Dashboard summary statistics."""
    all_reports = list_reports()
    total = len(all_reports)
    if total == 0:
        return {"total": 0, "malware": 0, "safe": 0, "high_risk": 0}

    categories = [r["category"] for r in all_reports]
    return {
        "total":        total,
        "critical":     categories.count("CRITICAL THREAT"),
        "high_risk":    categories.count("HIGH RISK"),
        "suspicious":   categories.count("SUSPICIOUS"),
        "low_risk":     categories.count("LOW RISK"),
        "avg_score":    round(sum(r["final_score"] for r in all_reports) / total, 1),
        "with_llm":     sum(1 for r in all_reports if r["has_llm"]),
    }


# ── Delete report ─────────────────────────────────────────────────────────────

@app.delete("/report/{apk_name}")
def delete_report(apk_name: str):
    """Delete an APK's analysis output."""
    folder = safe_output_dir(apk_name)
    if not folder.exists():
        raise HTTPException(status_code=404, detail=f"No report found for {apk_name}")
    shutil.rmtree(folder)
    return {"message": f"Report for {apk_name} deleted"}


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    print("\n" + "═" * 50)
    print("  APKGuard API starting...")
    print("  Dashboard: http://localhost:8000")
    print("  API Docs:  http://localhost:8000/docs")
    print("═" * 50 + "\n")
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
