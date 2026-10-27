CREATE TABLE IF NOT EXISTS members (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('owner','caller')),
 pin_salt TEXT NOT NULL,
 pin_hash TEXT NOT NULL,
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY,
 member_id TEXT NOT NULL REFERENCES members(id),
 expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS leads (
 id TEXT PRIMARY KEY,
 business TEXT NOT NULL,
 category TEXT NOT NULL CHECK(category IN ('wholesale','advertising','retail')),
 contact TEXT NOT NULL DEFAULT '',
 email TEXT NOT NULL DEFAULT '',
 phone TEXT NOT NULL DEFAULT '',
 website TEXT NOT NULL DEFAULT '',
 city TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'New',
 notes TEXT NOT NULL DEFAULT '',
 due TEXT NOT NULL DEFAULT '',
 last_sent TEXT NOT NULL DEFAULT '',
 assigned_to TEXT NOT NULL REFERENCES members(id),
 created_by TEXT NOT NULL REFERENCES members(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_pl_leads_assigned ON leads(assigned_to,updated_at);
CREATE TABLE IF NOT EXISTS events (
 id TEXT PRIMARY KEY,
 lead_id TEXT NOT NULL REFERENCES leads(id),
 member_id TEXT NOT NULL REFERENCES members(id),
 action TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);