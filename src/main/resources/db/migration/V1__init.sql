CREATE TABLE IF NOT EXISTS scan_job (
  id UUID PRIMARY KEY,
  repo_url TEXT NOT NULL,
  ref TEXT,
  tool TEXT NOT NULL CHECK (tool IN ('semgrep','cbomkit','both')),
  status TEXT NOT NULL CHECK (status IN ('QUEUED','RUNNING','COMPLETED','FAILED')),
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),
  semgrep_output JSONB,
  cbomkit_output JSONB,
  pqc_score INT,
  error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_job_semgrep ON scan_job USING GIN (semgrep_output);
CREATE INDEX IF NOT EXISTS idx_scan_job_cbom ON scan_job USING GIN (cbomkit_output);
