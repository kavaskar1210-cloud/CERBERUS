from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
import time
import requests


app = FastAPI(
    title="CERBERUS API Security Test Target",
    version="1.0.0"
)


# ============================================================
# API4 — Simple rate-limit simulation
# ============================================================

request_counter = 0
counter_start_time = time.time()

RATE_LIMIT = 5
RESET_TIME = 10


def check_rate_limit():

    global request_counter
    global counter_start_time

    current_time = time.time()

    if current_time - counter_start_time >= RESET_TIME:
        request_counter = 0
        counter_start_time = current_time

    request_counter += 1

    if request_counter > RATE_LIMIT:
        return False

    return True


# ============================================================
# Root
# ============================================================

@app.get("/")
def home():

    if not check_rate_limit():

        return JSONResponse(
            status_code=429,
            content={
                "error": "Too Many Requests",
                "message": "Rate limit exceeded"
            }
        )

    return {
        "message": "CERBERUS API Security Test Target"
    }


# ============================================================
# Public endpoint
# ============================================================

@app.get("/public")
def public_endpoint():

    return {
        "message": "Public endpoint"
    }


# ============================================================
# User endpoint
# ============================================================

@app.get("/users/{user_id}")
def get_user(user_id: int):

    return {
        "user_id": user_id,
        "username": "testuser",
        "email": "test@example.com"
    }


# ============================================================
# Admin endpoint
# ============================================================

@app.get("/admin")
def admin_endpoint(
    authorization: str | None = Header(default=None)
):

    if authorization != "Bearer test-admin-token":

        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )

    return {
        "message": "Admin access granted"
    }


# ============================================================
# Slow endpoint
# ============================================================

@app.get("/slow")
def slow_endpoint():

    time.sleep(2)

    return {
        "message": "Slow response"
    }


# ============================================================
# SSRF controlled internal resource
# ============================================================

@app.get("/internal-secret")
def internal_secret():

    return {
        "secret": "CERBERUS-SSRF-CANARY"
    }


# ============================================================
# SSRF test endpoint
# ============================================================

@app.get("/redirect")
def redirect_endpoint(
    url: str
):

    try:

        response = requests.get(
            url,
            timeout=3
        )

        return {
            "requested_url": url,
            "upstream_status": response.status_code,
            "upstream_response": response.text
        }

    except requests.RequestException as exc:

        return {
            "requested_url": url,
            "error": str(exc)
        }


# ============================================================
# API status
# ============================================================

@app.get("/api/v1/status")
def status():

    return {
        "status": "online"
    }