import asyncio
import functools
import logging
import time
import weakref
from datetime import datetime, timezone

import anyio
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

from backend.database import ORDERS, USERS
from backend.event_preprocessing import request_event_fields
from backend.security_logger import (
    SecurityEventPersistenceError,
    SecurityEventRejected,
    log_security_event,
)
from backend.dashboard_api import router as dashboard_router
from backend.gemini_api import router as gemini_router
from backend.metrics import HTTP_DURATION, HTTP_REQUESTS, SECURITY_EVENTS, route_label

logger = logging.getLogger(__name__)

# Logging threads queue on one write lock anyway. A separate limiter keeps
# a slow database from occupying the worker threads that sync routes share
# (anyio's default limiter); requests beyond it wait without a thread.
_LOGGING_THREADS = 4
_logging_limiters: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, anyio.CapacityLimiter]" = (
    weakref.WeakKeyDictionary()
)


def _logging_thread_limiter() -> anyio.CapacityLimiter:
    # One per event loop: a CapacityLimiter belongs to the loop it is used on.
    loop = asyncio.get_running_loop()
    limiter = _logging_limiters.get(loop)
    if limiter is None:
        limiter = _logging_limiters[loop] = anyio.CapacityLimiter(_LOGGING_THREADS)
    return limiter

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
app.include_router(gemini_router)


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


def _skip_security_logging(request: Request) -> bool:
    path = request.url.path
    if (
        path.startswith("/api/dashboard")
        or path.startswith("/metrics")
        or path in {"/docs", "/openapi.json", "/favicon.ico"}
    ):
        return True
    # CORS preflight: the browser asking permission, not an API call.
    return (
        request.method == "OPTIONS"
        and "origin" in request.headers
        and "access-control-request-method" in request.headers
    )


async def _record_security_event(
    request: Request,
    *,
    status_code: int,
    started_at: datetime,
    response_time_ms: float,
) -> None:
    """Log the request. Never raises: a logging problem must not change the
    response or replace the route's own exception."""
    try:
        fields = request_event_fields(
            method=request.method,
            path=request.url.path,
            headers=request.headers,
            client_host=request.client.host if request.client else None,
        )
        # SQLite and file I/O run in a worker thread, off the event loop.
        # Cancellation waits for a started write instead of abandoning it.
        await anyio.to_thread.run_sync(
            functools.partial(
                log_security_event,
                **fields,
                status_code=status_code,
                response_time_ms=response_time_ms,
                timestamp=started_at,
            ),
            limiter=_logging_thread_limiter(),
        )
    except (SecurityEventRejected, SecurityEventPersistenceError):
        pass  # Already logged and counted by backend.security_logger.
    except Exception:
        SECURITY_EVENTS.labels("failed").inc()
        logger.exception("Security event logging failed")
    except BaseException:
        # Cancellation (e.g. shutdown) before the write started: the event is
        # lost, so make that visible before letting cancellation proceed.
        SECURITY_EVENTS.labels("failed").inc()
        logger.warning("Security event logging cancelled; event for %s not stored", request.method)
        raise


@app.middleware("http")
async def security_logging_middleware(request: Request, call_next):
    if _skip_security_logging(request):
        return await call_next(request)

    started_at = datetime.now(timezone.utc)
    start_time = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        await _record_security_event(
            request,
            status_code=500,
            started_at=started_at,
            response_time_ms=(time.perf_counter() - start_time) * 1000,
        )
        raise

    await _record_security_event(
        request,
        status_code=response.status_code,
        started_at=started_at,
        response_time_ms=(time.perf_counter() - start_time) * 1000,
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
