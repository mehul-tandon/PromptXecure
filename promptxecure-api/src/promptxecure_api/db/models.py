"""
Database models and connection management.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from promptxecure_api.config import settings


class Base(DeclarativeBase):
    pass


class ScanLog(Base):
    """Stores every analyzed prompt with full metadata."""
    __tablename__ = "scan_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    prompt_hash = Column(String(64), index=True)
    prompt_preview = Column(String(200))
    risk_score = Column(Float, index=True)
    risk_level = Column(String(20), index=True)
    action = Column(String(20), index=True)
    model_used = Column(String(100), nullable=True)
    threats = Column(JSONB, default=list)
    layers = Column(JSONB, default=dict)
    processing_ms = Column(Integer, default=0)
    ip_address = Column(String(45), nullable=True)  # IPv6 max length
    sanitized_prompt = Column(Text, nullable=True)
    llm_response_preview = Column(String(500), nullable=True)


# Engine and session
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
    pool_recycle=1800,
    pool_pre_ping=True,
)

async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncSession:
    """Dependency: yield async DB session."""
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Create tables on startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
