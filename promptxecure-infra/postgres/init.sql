-- PromptXecure PostgreSQL Initialization Script
-- Runs once on first container startup

-- Create separate database for Langfuse (avoids Prisma migration conflict)
CREATE DATABASE langfuse;

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For text search

-- scan_logs table (also created by SQLAlchemy — this is for the init only)
CREATE TABLE IF NOT EXISTS scan_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now(),
    prompt_hash     VARCHAR(64),
    prompt_preview  VARCHAR(200),
    risk_score      FLOAT,
    risk_level      VARCHAR(20),
    action          VARCHAR(20),
    model_used      VARCHAR(100),
    threats         JSONB DEFAULT '[]'::jsonb,
    layers          JSONB DEFAULT '{}'::jsonb,
    processing_ms   INTEGER DEFAULT 0,
    ip_address      VARCHAR(45),
    sanitized_prompt TEXT,
    llm_response_preview VARCHAR(500)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_scan_logs_timestamp    ON scan_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_scan_logs_risk_score   ON scan_logs (risk_score);
CREATE INDEX IF NOT EXISTS idx_scan_logs_risk_level   ON scan_logs (risk_level);
CREATE INDEX IF NOT EXISTS idx_scan_logs_action       ON scan_logs (action);
CREATE INDEX IF NOT EXISTS idx_scan_logs_prompt_hash  ON scan_logs (prompt_hash);
CREATE INDEX IF NOT EXISTS idx_scan_logs_prompt_preview ON scan_logs USING gin(prompt_preview gin_trgm_ops);

-- For JSONB queries
CREATE INDEX IF NOT EXISTS idx_scan_logs_threats      ON scan_logs USING gin(threats jsonb_path_ops);

-- Partition suggestion for production (commented out — requires pg_partman)
-- ALTER TABLE scan_logs PARTITION BY RANGE (timestamp);
