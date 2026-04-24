import asyncio
import queue
import json
import threading
from datetime import datetime, timezone
from fastapi import FastAPI, WebSocket, Depends, HTTPException, Security, Query
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from online.alert_store import (
    init_db,
    save_alert,
    update_cti,
    get_recent_alerts,
    get_stats
)
from online.alert_queue import alert_queue, get_stats as get_engine_stats_queue
from online.cti_cache import get_cti_stats

# We must import get_stats from nfstream engine as well
from online.nfstream_engine import get_stats as get_engine_stats_nfstream

_ws_clients: set = set()
_loop: asyncio.AbstractEventLoop = None
_server_stats = {"queued": 0, "saved": 0, "ws_pushes": 0}

def get_engine_stats():
    # Merge stats from queue and nfstream
    nf = get_engine_stats_nfstream()
    ml = get_engine_stats_queue()
    return {"engine": {**nf, **ml}}

async def _broadcast(message: str):
    dead = set()
    for ws in _ws_clients:
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    _ws_clients -= dead

def _broadcast_sync(message: str, loop):
    asyncio.run_coroutine_threadsafe(_broadcast(message), loop)

_API_KEY = "xti_soc_secure_2024"
_API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=_API_KEY_NAME, auto_error=False)

def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != _API_KEY:
        raise HTTPException(status_code=403, detail="Could not validate API key")
    return api_key

def _processing_worker(loop):
    while True:
        try:
            alert = alert_queue.get(timeout=1.0)
        except queue.Empty:
            continue
            
        # DROP BENIGN TRAFFIC
        is_benign = alert.get("ml_class") == "BENIGN" and alert.get("attack_type") == "BENIGN"
        cti = alert.get("cti_data") or {}
        if is_benign and cti.get("alert_type") != "CTI_ONLY":
            continue

        try:
            save_alert(alert)
            _server_stats["saved"] += 1
            msg = json.dumps(alert, default=str)
            _broadcast_sync(msg, loop)
            _server_stats["ws_pushes"] += 1
        except Exception as e:
            print(f"[WORKER ERROR] {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    global _loop
    _loop = asyncio.get_event_loop()
    threading.Thread(target=_processing_worker, args=(_loop,), daemon=True).start()
    yield
    # Shutdown

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="XTI-SOC", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://10.20.42.183:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response

@app.get("/alerts")
@limiter.limit("100/minute")
def read_alerts(request: Request, limit: int = 50, api_key: str = Depends(verify_api_key)):
    return get_recent_alerts(limit)

@app.get("/stats")
@limiter.limit("60/minute")
def read_stats(request: Request, api_key: str = Depends(verify_api_key)):
    db_stats = get_stats()
    engine_stats = get_engine_stats()
    cti_stats = get_cti_stats()
    return {
        **db_stats,
        "engine_stats": engine_stats,
        "cti_stats": cti_stats,
        **_server_stats
    }

@app.get("/health")
@limiter.limit("10/minute")
def health(request: Request):
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket, token: str = Query(None)):
    if token != _API_KEY:
        await websocket.close(code=1008)
        return
        
    await websocket.accept()
    _ws_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        pass
    finally:
        _ws_clients.discard(websocket)
