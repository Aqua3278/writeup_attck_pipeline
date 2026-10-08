PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sources (
  source_id TEXT PRIMARY KEY,
  source_name TEXT NOT NULL,
  source_type TEXT,
  entry_url TEXT,
  adapter_type TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  crawl_config_json TEXT,
  last_crawl_time TEXT,
  status TEXT DEFAULT 'idle'
);

CREATE TABLE IF NOT EXISTS writeups (
  writeup_id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL,
  source_name TEXT,
  title TEXT,
  canonical_url TEXT,
  task_name TEXT,
  benchmark_name TEXT,
  published_at TEXT,
  crawled_at TEXT,
  content_format TEXT,
  raw_content_path TEXT,
  parsed_content_path TEXT,
  content_hash TEXT,
  linked_resources_json TEXT,
  crawl_status TEXT,
  parse_status TEXT,
  version INTEGER DEFAULT 1,
  error TEXT,
  attack_chain_source TEXT,
  coverage_status TEXT DEFAULT 'pending',
  chain_paths_json TEXT,
  chain_notes TEXT,
  UNIQUE(source_id, canonical_url, content_hash)
);

CREATE TABLE IF NOT EXISTS writeup_versions (
  writeup_id TEXT,
  version INTEGER,
  content_hash TEXT,
  raw_content_path TEXT,
  crawled_at TEXT,
  PRIMARY KEY (writeup_id, version)
);

CREATE TABLE IF NOT EXISTS crawl_failures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id TEXT,
  url TEXT,
  error TEXT,
  attempts INTEGER DEFAULT 1,
  last_attempt_at TEXT,
  resolved INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS attack_steps (
  step_id TEXT PRIMARY KEY,
  writeup_id TEXT NOT NULL,
  sequence INTEGER,
  action TEXT,
  target TEXT,
  input TEXT,
  output TEXT,
  purpose TEXT,
  prerequisite TEXT,
  evidence TEXT,
  evidence_location TEXT,
  evidence_type TEXT,
  inference INTEGER,
  confidence REAL,
  chunk_id TEXT,
  created_at TEXT,
  step_type TEXT DEFAULT 'other',
  phase TEXT DEFAULT '其他',
  chain_status TEXT DEFAULT 'pending',
  chain_reason TEXT DEFAULT '',
  path_id TEXT DEFAULT '',
  depends_on_json TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS path_edges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  writeup_id TEXT NOT NULL,
  from_step_id TEXT,
  to_step_id TEXT,
  relation TEXT
);

CREATE TABLE IF NOT EXISTS technique_catalog (
  technique_id TEXT NOT NULL,
  technique_name TEXT,
  tactic TEXT NOT NULL,
  description TEXT,
  retained INTEGER,
  source_workbook TEXT,
  loaded_at TEXT,
  PRIMARY KEY (technique_id, tactic)
);

CREATE TABLE IF NOT EXISTS technique_mappings (
  mapping_id TEXT PRIMARY KEY,
  step_id TEXT,
  writeup_id TEXT,
  technique_id TEXT,
  technique_name TEXT,
  tactic TEXT,
  mapping_status TEXT,
  mapping_type TEXT,
  mapping_reason TEXT,
  evidence TEXT,
  evidence_location TEXT,
  confidence REAL,
  review_status TEXT,
  created_at TEXT,
  mapping_role TEXT DEFAULT 'sole',
  supporting_behavior TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS validation_issues (
  issue_id TEXT PRIMARY KEY,
  writeup_id TEXT,
  step_id TEXT,
  mapping_id TEXT,
  severity TEXT,
  code TEXT,
  message TEXT,
  details_json TEXT,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS human_reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_type TEXT,
  target_id TEXT,
  reviewer TEXT,
  action TEXT,
  original_json TEXT,
  revised_json TEXT,
  reason TEXT,
  reviewed_at TEXT
);

CREATE TABLE IF NOT EXISTS run_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT,
  stage TEXT,
  config_json TEXT,
  started_at TEXT,
  finished_at TEXT,
  status TEXT,
  message TEXT
);