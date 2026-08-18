import logging
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from app.config import get_settings
from app.scanner.service import scan

logging.basicConfig(level=logging.INFO)
settings=get_settings(); app=FastAPI(title="VulnScan Lite API", docs_url=None if settings.environment=="production" else "/docs")
if settings.origins: app.add_middleware(CORSMiddleware, allow_origins=settings.origins, allow_credentials=False, allow_methods=["GET","POST"], allow_headers=["Content-Type"])
jobs: dict[str,dict] = {}; executor=ThreadPoolExecutor(max_workers=4)
request_buckets: dict[str, list[float]] = {}
class ScanRequest(BaseModel): url: HttpUrl

@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if request.url.path == "/api/scan" and request.method == "POST":
        now=time.monotonic(); client=request.client.host if request.client else "unknown"
        bucket=[moment for moment in request_buckets.get(client, []) if now-moment < 60]
        if len(bucket) >= 10:
            return JSONResponse({"detail":"Too many scan requests. Please try again shortly."}, status_code=429)
        bucket.append(now); request_buckets[client]=bucket
    return await call_next(request)
@app.get("/health")
def health(): return {"status":"healthy"}
def run_job(job_id: str, url: str):
    jobs[job_id]["status"]="running"
    try: jobs[job_id].update(status="completed", result=scan(url, settings.request_timeout_seconds))
    except Exception as error:
        logging.exception("Scan failed: %s", job_id); jobs[job_id].update(status="failed", error="Scan could not be completed safely.")
@app.post("/api/scan", status_code=202)
def create_scan(payload: ScanRequest):
    job_id=str(uuid4()); jobs[job_id]={"id":job_id,"status":"queued"}; executor.submit(run_job,job_id,str(payload.url)); return {"id":job_id,"status":"queued"}
@app.get("/api/scan/{job_id}/status")
def scan_status(job_id: str):
    job=jobs.get(job_id)
    if not job: raise HTTPException(404,"Scan not found.")
    return {key:value for key,value in job.items() if key != "result"}
@app.get("/api/scan/{job_id}/result")
def scan_result(job_id: str):
    job=jobs.get(job_id)
    if not job: raise HTTPException(404,"Scan not found.")
    if job["status"]=="failed": raise HTTPException(422,job.get("error","Scan failed."))
    if job["status"]!="completed": raise HTTPException(409,"Scan is not complete.")
    return job["result"]
