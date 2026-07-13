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
    global _ws_clients
    dead = set()
    for ws in _ws_clients:
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    _ws_clients -= dead



import os
_API_KEY = os.environ.get("XTI_SOC_API_KEY")
if not _API_KEY:
    raise RuntimeError("XTI_SOC_API_KEY not set. Aborting.")
_API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=_API_KEY_NAME, auto_error=False)

def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != _API_KEY:
        raise HTTPException(status_code=403, detail="Could not validate API key")
    return api_key

def _broadcast_sync(message: str, loop):
    try:
        future = asyncio.run_coroutine_threadsafe(_broadcast(message), loop)
        future.result(timeout=2.0)
    except Exception as e:
        print(f"[WS BROADCAST ERROR] {e}")

def _processing_worker(loop):
    while True:
        try:
            alert = alert_queue.get(timeout=1.0)
        except queue.Empty:
            continue
            
        # DROP BENIGN TRAFFIC
        ml_class = alert.get('ml_class', 'BENIGN')
        alert_type = (alert.get('cti_data') or {}).get('alert_type', 'NO_ALERT')
        if alert_type in ('NO_ALERT', None) and ml_class == 'BENIGN':
            continue  # truly benign, no CTI flag either — drop

        try:
            save_alert(alert)
            _server_stats["saved"] += 1
            msg = json.dumps(alert, default=str)
            print(f"[WS] Preparing to broadcast {alert.get('alert_type')} to {len(_ws_clients)} clients...")
            _broadcast_sync(msg, loop)
            _server_stats["ws_pushes"] += 1
            print("[WS] Broadcast successful.")
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

def get_real_ip(request: Request) -> str:
    return request.client.host or "127.0.0.1"

limiter = Limiter(key_func=get_real_ip)
app = FastAPI(title="XTI-SOC", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_text()
        msg = json.loads(data)
        if msg.get("token") != _API_KEY:
            await websocket.close(code=1008)
            return
            
        _ws_clients.add(websocket)
        while True:
            await websocket.receive_text()
    except Exception:
        pass
    finally:
        _ws_clients.discard(websocket)
