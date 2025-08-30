import os, json, asyncio, time
from typing import AsyncGenerator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
HOST_EVENTS = os.path.join(DATA_DIR, "host_isolation_events.json")

app = FastAPI(title="CyberNOVA Events")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_events():
    try:
        if not os.path.exists(HOST_EVENTS): return []
        with open(HOST_EVENTS, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

async def sse_generator() -> AsyncGenerator[bytes, None]:
    last_len = 0
    while True:
        try:
            evs = load_events()
            if len(evs) > last_len:
                for ev in evs[last_len:]:
                    yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode("utf-8")
                last_len = len(evs)
            await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(1.0)

@app.get("/events/alerts")
async def events_alerts():
    return StreamingResponse(sse_generator(), media_type="text/event-stream")

@app.get("/health")
async def health():
    return JSONResponse({"ok": True, "ts": time.time()})
