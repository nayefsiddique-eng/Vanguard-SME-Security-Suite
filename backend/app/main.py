from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.requests import Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.db.database import engine, Base
from app.core.config import ALLOWED_ORIGINS

# Router imports
from app.api.routes_auth import router as auth_router
from app.api.routes_scan import router as scan_router
from app.api.routes_history import router as history_router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Vanguard SME Security Suite API",
    description="Backend API for Vanguard SME Security Suite, a unified multi-vector cybersecurity scanning and rolling posture assessment platform."
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"error": "Rate limit exceeded. Try again later."}
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include APIs
app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(history_router)
