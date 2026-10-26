from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.openapi.utils import get_openapi


app = FastAPI(
    title="CERBERUS Test API",
    version="1.0.0"
)


# --------------------------------------------------
# Authentication scheme for CERBERUS API2 testing
# --------------------------------------------------

def custom_openapi():

    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title,
        version=app.version,
        routes=app.routes
    )

    schema.setdefault("components", {})

    schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }

    schema["security"] = [
        {
            "BearerAuth": []
        }
    ]

    app.openapi_schema = schema

    return schema


app.openapi = custom_openapi


# --------------------------------------------------
# Basic API endpoint
# --------------------------------------------------

@app.get("/")
def home():

    return {
        "message": "CERBERUS controlled test API",
        "status": "online"
    }


# --------------------------------------------------
# Internal canary for API7 SSRF testing
# --------------------------------------------------

@app.get("/internal-secret")
def internal_secret():

    return PlainTextResponse(
        "CERBERUS-SSRF-CANARY"
    )


# --------------------------------------------------
# URL-fetch simulation for API7
# --------------------------------------------------

@app.get("/redirect")
def redirect(url: str):

    return {
        "requested_url": url
    }


# --------------------------------------------------
# Rate-limit test endpoint for API4
# --------------------------------------------------

request_counter = 0


@app.get("/rate-limit-test")
def rate_limit_test(request: Request):

    global request_counter

    request_counter += 1

    if request_counter >= 3:

        return PlainTextResponse(
            "Rate limit triggered",
            status_code=429,
            headers={
                "Cache-Control": "no-store"
            }
        )

    return PlainTextResponse(
        f"Request {request_counter} allowed",
        status_code=200,
        headers={
            "Cache-Control": "no-store"
        }
    )


# --------------------------------------------------
# API9 inventory examples
# --------------------------------------------------

@app.get("/api/v1/users")
def users():

    return {
        "users": []
    }


@app.get("/api/v1/products")
def products():

    return {
        "products": []
    }


@app.get("/api/v2/users")
def users_v2():

    return {
        "users": []
    }