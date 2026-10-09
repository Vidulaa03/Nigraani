import time
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

from backend.database import ORDERS, USERS
from backend.security_logger import log_security_event
from backend.dashboard_api import router as dashboard_router
from backend.metrics import HTTP_DURATION, HTTP_REQUESTS, route_label

app = FastAPI(
    title="NIGRAANI",
    description="API for NIGRAANI abuse detection and monitoring",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard_router, prefix="/api/dashboard")


@app.middleware("http")
async def prometheus_http_metrics(request: Request, call_next):
    if request.url.path == "/metrics" or request.url.path.startswith("/metrics/"):
        return await call_next(request)

    started = time.perf_counter()
    try:
        response = await call_next(request)
        status = response.status_code
    except Exception:
        status = 500
        raise
    finally:
        elapsed = time.perf_counter() - started
        route = route_label(request)
        HTTP_REQUESTS.labels(request.method, route, str(status)).inc()
        HTTP_DURATION.labels(request.method, route).observe(elapsed)
    return response


@app.get("/metrics", include_in_schema=False)
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.middleware("http")
async def security_logging_middleware(request: Request, call_next):
    start_time = time.perf_counter()
    response = await call_next(request)
    response_time_ms = (time.perf_counter() - start_time) * 1000

    forwarded_ip = request.headers.get("X-Forwarded-For")
    if forwarded_ip:
        ip = forwarded_ip.split(",")[0].strip()
    else:
        ip = request.client.host if request.client else "unknown"

    user_id = request.headers.get("X-User-ID")
    if user_id is not None:
        try:
            user_id = int(user_id)
        except ValueError:
            user_id = None

    resource_id = None
    resource_owner_id = None
    endpoint = request.url.path
    if endpoint.startswith("/api/dashboard") or endpoint.startswith("/metrics") or endpoint in {"/docs", "/openapi.json", "/favicon.ico"}:
        return response

    if endpoint.startswith("/api/orders/"):
        try:
            resource_id = int(endpoint.rsplit("/", 1)[-1])
        except ValueError:
            resource_id = None

        if resource_id in ORDERS:
            resource_owner_id = ORDERS[resource_id].get("owner_id")

    log_security_event(
        ip=ip,
        method=request.method,
        endpoint=endpoint,
        status_code=response.status_code,
        response_time_ms=response_time_ms,
        user_id=user_id,
        resource_id=resource_id,
        resource_owner_id=resource_owner_id,
        sim_label=request.headers.get("X-Sim-Label", "normal"),
    )

    return response


@app.get("/")
def home():
    return {
        "message": "NIGRAANI is running",
        "status": "online"
    }


@app.get("/api/users/{user_id}")
def get_user(user_id: int):

    if user_id not in USERS:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return {
        "user_id": user_id,
        **USERS[user_id]
    }


@app.get("/api/orders/{order_id}")
def get_order(
    order_id: int,
    x_user_id: int = Header(...)
):

    if order_id not in ORDERS:
        raise HTTPException(
            status_code=404,
            detail="Order not found"
        )

    order = ORDERS[order_id]

    # Intentionally vulnerable endpoint.
    # Our security system will detect BOLA.

    return {
        "order_id": order_id,
        "requested_by": x_user_id,
        **order
    }


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
def login(login_request: LoginRequest):

    if login_request.username == "admin" and login_request.password == "admin123":
        return {
            "success": True,
            "message": "Login successful"
        }

    # Return HTTP 401 so the security logger and
    # login-failure detector correctly count failed logins.
    raise HTTPException(
        status_code=401,
        detail="Invalid username or password"
    )
