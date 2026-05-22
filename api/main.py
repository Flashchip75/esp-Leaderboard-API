from fastapi import FastAPI, Query, HTTPException, Depends, Request, Security
from fastapi.security.api_key import APIKeyHeader, APIKeyQuery
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import redis
import os
import time
import re

app = FastAPI()

# ── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "").split(","),
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["X-API-Key"],
)

# ── Security headers ──────────────────────────────────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# ── API key auth (header OR query param) ─────────────────────────────────────
API_KEY = os.getenv("API_KEY")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
api_key_query  = APIKeyQuery(name="api_key",    auto_error=False)

async def require_api_key(
    key_header: str = Security(api_key_header),
    key_query:  str = Security(api_key_query),
):
    if not API_KEY:
        raise RuntimeError("API_KEY env var is not set")
    key = key_header or key_query
    if key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing API key")
    return key

# ── Input sanitization ────────────────────────────────────────────────────────
USERNAME_RE = re.compile(r'^[a-zA-Z0-9_\-]{1,32}$')

def sanitize_user(user: str) -> str:
    if not USERNAME_RE.match(user):
        raise HTTPException(status_code=422, detail="Invalid username format")
    return user

# ── Redis ─────────────────────────────────────────────────────────────────────
r = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=6379,
    decode_responses=True
)

LEADERBOARD_KEY = "leaderboard:points"
STATS_KEY       = "stats"

# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/update", dependencies=[Depends(require_api_key)])
def update(
    user:     str = Query(...),
    distance: int = Query(..., ge=0, le=1_000_000),
    points:   int = Query(..., ge=0, le=1_000_000),
    goal:     int = Query(..., ge=0, le=1_000_000),
):
    user = sanitize_user(user)
    r.zadd(LEADERBOARD_KEY, {user: points})
    r.hset(f"{STATS_KEY}:{user}", mapping={
        "distance":    distance,
        "points":      points,
	"goal":	       goal,
        "last_update": int(time.time())
    })
    return {"status": "ok"}

@app.get("/leaderboard", dependencies=[Depends(require_api_key)])
def leaderboard(limit: int = Query(10, ge=1, le=100)):
    top = r.zrevrange(LEADERBOARD_KEY, 0, limit - 1, withscores=True)
    result = []
    for user, points in top:
        stats = r.hgetall(f"{STATS_KEY}:{user}")
        result.append({
            "user":        user,
            "points":      int(points),
            "distance":    int(stats.get("distance", 0)),
	    "goal":	   int(stats.get("goal", 0)),
            "last_update": int(stats.get("last_update", 0))
        })
    return resultW