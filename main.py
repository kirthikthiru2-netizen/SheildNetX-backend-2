"""
ShieldNetX Backend — fresh rebuild (rule-based, 11 signals, no ML model).

Run locally:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000

Deploy on Render:
    Start command -> uvicorn main:app --host 0.0.0.0 --port $PORT
"""

from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from signals import SIGNAL_FUNCTIONS, SIGNAL_WEIGHTS
from apk_router import router as apk_router
from db import init_db

app = FastAPI(
    title="ShieldNetX Backend",
    version="2.2.0",
    description="Rule-based phishing URL scanner + GenAI APK risk analysis with scan history.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this to your app's origin before production
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(apk_router)


@app.on_event("startup")
def on_startup():
    init_db()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    url: str = Field(..., description="The URL to scan, e.g. https://example.com/login")


class SignalResult(BaseModel):
    name: str
    score: float | None  # null means this signal couldn't be evaluated
    triggered: bool
    reason: str
    weight: float


class ScanResponse(BaseModel):
    url: str
    threat_score: float
    verdict: str
    signals: list[SignalResult]
    scanned_at: str


# ---------------------------------------------------------------------------
# Verdict thresholds
# ---------------------------------------------------------------------------

def verdict_for(score: float) -> str:
    if score >= 65:
        return "DANGEROUS"
    if score >= 30:
        return "SUSPICIOUS"
    return "SAFE"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return {"status": "ok", "service": "ShieldNetX Backend", "version": "2.0.0"}


@app.get("/health")
def health():
    return {"status": "healthy", "time": datetime.now(timezone.utc).isoformat()}


@app.post("/scan", response_model=ScanResponse)
def scan_url(payload: ScanRequest):
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL must not be empty")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    results: list[SignalResult] = []
    weighted_sum = 0.0
    active_weight = 0.0  # sum of weights for signals that actually produced a score

    for name, weight in SIGNAL_WEIGHTS.items():
        func = SIGNAL_FUNCTIONS[name]
        try:
            score, triggered, reason = func(url)
        except Exception as e:
            score, triggered, reason = None, False, f"Signal error: {e}"

        results.append(SignalResult(
            name=name, score=score, triggered=triggered, reason=reason, weight=weight,
        ))

        if score is not None:
            weighted_sum += score * weight
            active_weight += weight

    # Renormalize over only the signals that returned real data, so an
    # unreachable site (timeouts abstaining) doesn't dilute the score
    # toward "safe" just because several signals couldn't run — and so
    # repeat scans of the same URL give the same result regardless of
    # which network calls happen to succeed that time.
    if active_weight > 0:
        total_score = round(min((weighted_sum / active_weight), 100.0), 2)
    else:
        total_score = 0.0

    return ScanResponse(
        url=url,
        threat_score=total_score,
        verdict=verdict_for(total_score),
        signals=results,
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )
