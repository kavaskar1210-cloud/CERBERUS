import json

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from pydantic import BaseModel

from database import SessionLocal
from models.scan import Scan

from web_security.scanner import scan_target
from api_security.scanner import scan_api

from auth.routes import router as auth_router
from auth.auth import get_current_user

from security_operations.routes import (
    router as security_operations_router
)


app = FastAPI(
    title="CERBERUS",
    description="Cybersecurity Assessment & Response Platform",
    version="1.0.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(auth_router)

app.include_router(
    security_operations_router
)


@app.middleware("http")
async def security_headers(request, call_next):

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"

    response.headers["X-Frame-Options"] = "DENY"

    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )

    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
        "https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' "
        "https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com; "
        "font-src 'self' data: https://cdn.jsdelivr.net; "
        "connect-src 'self'"
    )

    return response


class ScanRequest(BaseModel):
    url: str


class APIScanRequest(BaseModel):
    url: str
    openapi_url: str | None = None


@app.get("/")
def home():

    return {
        "message": "CERBERUS backend is running",
        "status": "online"
    }


@app.post("/web-security/scan")
def web_security_scan(
    request: ScanRequest,
    current_user: dict = Depends(get_current_user)
):

    results = scan_target(request.url)

    db = SessionLocal()

    try:

        scan = Scan(
            target_url=request.url,
            status=results.get(
                "status",
                "unknown"
            ),
            scan_type="web",
            results=json.dumps(results)
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        return {
            "scan_id": scan.id,
            "status": "saved",
            "scanned_by": current_user["username"],
            "results": results
        }

    finally:

        db.close()


@app.post("/api-security/scan")
def api_security_scan(
    request: APIScanRequest,
    current_user: dict = Depends(get_current_user)
):

    results = scan_api(
        request.url,
        request.openapi_url
    )

    db = SessionLocal()

    try:

        scan = Scan(
            target_url=request.url,
            status=results.get(
                "status",
                "unknown"
            ),
            scan_type="api",
            results=json.dumps(results)
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        return {
            "scan_id": scan.id,
            "status": "saved",
            "scanned_by": current_user["username"],
            "results": results
        }

    finally:

        db.close()