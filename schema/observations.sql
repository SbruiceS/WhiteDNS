-- WhiteDNS observation schema (Phase 6 SQLite/Postgres). Phase 1 writes JSONL.
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  qname TEXT NOT NULL,
  qtype INTEGER NOT NULL,
  resolver TEXT NOT NULL,
  transport TEXT NOT NULL,
  rcode INTEGER,
  flags TEXT,
  rtt_ms INTEGER,
  ts INTEGER NOT NULL,
  packet_sha256 TEXT
);
CREATE TABLE IF NOT EXISTS records (
  id INTEGER PRIMARY KEY,
  observation_id INTEGER NOT NULL,
  owner TEXT,
  type INTEGER,
  ttl INTEGER,
  rdata_text TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  severity TEXT,
  confidence TEXT,
  class TEXT,
  ts INTEGER NOT NULL
);
