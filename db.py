"""
ShieldNetX database layer.

Local dev: uses a SQLite file (shieldnetx.db) with zero setup.
Production (Render): set the DATABASE_URL environment variable to a
Postgres connection string (e.g. from Render's free Postgres add-on)
and this switches over automatically — no code changes needed.
"""

import os
import json
from datetime import datetime, timezone

from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./shieldnetx.db")

# Render (and most hosts) give a plain "postgres://" or "postgresql://" URL.
# SQLAlchemy 2.x's default driver for that prefix is ambiguous depending on
# what's installed, so pin it explicitly to psycopg2 (which we install via
# requirements.txt) to avoid a "no module named psycopg" surprise in prod.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

# SQLite needs this flag for use across FastAPI's threaded request handling;
# Postgres doesn't need it (or accept it), so only pass it for SQLite.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ApkScanRecord(Base):
    __tablename__ = "apk_scans"

    id = Column(Integer, primary_key=True, index=True)
    sha256 = Column(String(64), unique=True, index=True, nullable=False)
    filename = Column(String(255))
    package_name = Column(String(255), nullable=True)
    app_name = Column(String(255), nullable=True)

    static_score = Column(Float)
    dynamic_score = Column(Float)
    ai_score = Column(Float, nullable=True)
    risk_score = Column(Float)
    verdict = Column(String(20))

    # Stored as JSON text — SQLite has no native JSON column, and this
    # keeps the schema identical when we move to Postgres later.
    permissions_found_json = Column(Text)
    suspicious_apis_json = Column(Text)
    dynamic_indicators_json = Column(Text)
    embedded_urls_json = Column(Text)
    recommendations_json = Column(Text)

    ai_summary = Column(Text)

    first_analyzed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_analyzed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    scan_count = Column(Integer, default=1)


class KnownMalwareHash(Base):
    """Self-contained threat-intel blocklist. Populated two ways:
    (1) manually, for known malware samples you want to seed ahead of time
    (2) automatically, whenever ShieldNetX's own analysis reaches a
        DANGEROUS verdict — so anything caught once is instantly
        recognized on every future submission, with zero external calls.
    """
    __tablename__ = "known_malware_hashes"

    id = Column(Integer, primary_key=True, index=True)
    sha256 = Column(String(64), unique=True, index=True, nullable=False)
    label = Column(String(255), nullable=True)   # e.g. "Banking trojan - overlay/SMS"
    source = Column(String(50))                   # "shieldnetx_detection" or "manual"
    added_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Helpers to convert between the API's Pydantic models and DB rows
# ---------------------------------------------------------------------------

def record_to_dict(record: ApkScanRecord) -> dict:
    return {
        "sha256": record.sha256,
        "filename": record.filename,
        "package_name": record.package_name,
        "app_name": record.app_name,
        "static_score": record.static_score,
        "dynamic_score": record.dynamic_score,
        "ai_score": record.ai_score,
        "risk_score": record.risk_score,
        "verdict": record.verdict,
        "permissions_found": json.loads(record.permissions_found_json or "[]"),
        "suspicious_apis": json.loads(record.suspicious_apis_json or "[]"),
        "dynamic_indicators": json.loads(record.dynamic_indicators_json or "[]"),
        "embedded_urls": json.loads(record.embedded_urls_json or "[]"),
        "recommendations": json.loads(record.recommendations_json or "[]"),
        "ai_summary": record.ai_summary,
        "first_analyzed_at": record.first_analyzed_at.isoformat() if record.first_analyzed_at else None,
        "last_analyzed_at": record.last_analyzed_at.isoformat() if record.last_analyzed_at else None,
        "scan_count": record.scan_count,
    }
